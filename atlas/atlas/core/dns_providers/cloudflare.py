from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping, override
from uuid import uuid4

import requests

from atlas.atlas.core.dns_providers import register
from atlas.atlas.core.dns_providers.base import DnsProvider

if TYPE_CHECKING:
	from atlas.atlas.doctype.atlas_settings.atlas_settings import AtlasSettings

API_BASE_URL = "https://api.cloudflare.com/client/v4"
ZONE_PAGE_SIZE = 50
MAXIMUM_ZONE_PAGES = 20


class CloudflareError(Exception):
	"""Raised when Cloudflare rejects a provider request."""


class CloudflareClient:
	"""Send authenticated requests to the Cloudflare API."""

	def __init__(self, api_token: str) -> None:
		self.api_token = api_token

	def request(
		self, method: str, path: str, params: Mapping | None = None, payload: Mapping | None = None
	) -> Any:
		try:
			response = requests.request(
				method,
				f"{API_BASE_URL}{path}",
				headers={"Authorization": f"Bearer {self.api_token}"},
				params=dict(params or {}),
				json=dict(payload) if payload else None,
				timeout=(5, 30),
			)
		except requests.RequestException as error:
			raise CloudflareError(f"Cloudflare API {method} {path} is unreachable: {error}") from error

		if response.status_code >= 400 or not self.is_successful(response):
			raise CloudflareError(f"Cloudflare API {method} {path} failed: {self.error_text(response)}")

		result = response.json().get("result")
		return result

	@staticmethod
	def is_successful(response: requests.Response) -> bool:
		try:
			body = response.json()
		except ValueError:
			return False
		return isinstance(body, dict) and body.get("success") is True

	@staticmethod
	def error_text(response: requests.Response) -> str:
		try:
			body = response.json()
		except ValueError:
			return ""
		errors = body.get("errors") if isinstance(body, dict) else None
		if isinstance(errors, list) and errors and isinstance(errors[0], Mapping):
			message = errors[0].get("message")
			if isinstance(message, str):
				return message
		return ""


@register
class CloudflareProvider(DnsProvider):
	"""Manage DNS records in the Cloudflare zones of one account.

	Cloudflare has no record-level health checks outside its paid load balancer,
	so health check IDs are local placeholders and multivalue A records are plain
	round-robin records identified by their comment.
	"""

	provider_type = "Cloudflare"
	credential_fields = ("cloudflare_api_token",)

	def __init__(self, settings: "AtlasSettings | None" = None) -> None:
		super().__init__(settings)
		self.domain_name = self.settings.wildcard_domain.removeprefix("*.")
		self.client = CloudflareClient(
			self.settings.get_password("cloudflare_api_token", raise_exception=False) or ""
		)

	@override
	def validate_settings(self) -> None:
		"""Check the wildcard domain."""
		if "." not in self.domain_name:
			raise CloudflareError(f"Invalid Atlas wildcard domain: {self.settings.wildcard_domain}")

	@override
	def bootstrap(self) -> None:
		"""Set up the Cloudflare resources used by Atlas."""
		self.settings.cloudflare_zone_id = self.create_zone(self.domain_name)
		self.upsert_cname_record(
			f"*.{self.domain_name}",
			f"proxy.{self.domain_name}",
			ttl=3600,
		)

		self.settings.is_dns_setup_completed = 1
		self.settings.save()

	@override
	def validate_credentials(self) -> bool:
		"""Return true when the configured token can list zones."""
		self.client.request("GET", "/zones", {"per_page": 1})
		return True

	@override
	def get_zone_id(self, domain: str) -> str | None:
		"""Return the ID of the account zone named exactly `domain`, or None."""
		return self.find_public_zone_id(domain)

	@override
	def find_public_zone_id(self, domain: str) -> str | None:
		"""Return the ID of an existing public zone for the exact domain."""
		for zone in self.zones():
			if zone.get("name") == domain and isinstance(zone.get("id"), str):
				return zone["id"]
		return None

	@override
	def create_zone(self, domain: str) -> str:
		"""Return the closest account zone for the domain.

		Non-enterprise Cloudflare accounts hold one zone per registrable domain, so
		Atlas reuses the zone whose name is the longest suffix of the domain instead
		of creating a subdomain zone.
		"""
		names = [zone["name"] for zone in self.zones() if isinstance(zone.get("name"), str)]
		matches = [name for name in names if domain == name or domain.endswith(f".{name}")]
		if not matches:
			raise CloudflareError(f"Add the {domain!r} zone, or its parent zone, to the Cloudflare account")
		return max(matches, key=len)

	@override
	def upsert_record(self, record_type: str, name: str, values: list[str], ttl: int = 300) -> None:
		"""Create the DNS record if missing, or update the first match to the first value."""
		zone_id = self.create_zone(name)
		existing = self.list_records(zone_id, record_type, name)
		payload = {"type": record_type, "name": name, "content": values[0], "ttl": ttl, "proxied": False}
		if existing:
			self.client.request(
				"PUT", f"/zones/{zone_id}/dns_records/{existing[0]['id']}", payload=payload
			)
		else:
			self.client.request("POST", f"/zones/{zone_id}/dns_records", payload=payload)

	@override
	def remove_record(self, record_type: str, name: str) -> None:
		"""Remove every DNS record for the name and type."""
		zone_id = self.create_zone(name)
		for record in self.list_records(zone_id, record_type, name):
			self.client.request("DELETE", f"/zones/{zone_id}/dns_records/{record['id']}")

	@override
	def create_https_health_check(self, ip_address: str, domain: str, path: str) -> str:
		"""Return a local placeholder, because Cloudflare has no record-level health checks."""
		return f"cloudflare-{uuid4()}"

	@override
	def remove_health_check(self, health_check_id: str) -> None:
		"""Remove nothing, because the health check is a local placeholder."""

	@override
	def upsert_multivalue_a_record(
		self,
		name: str,
		identifier: str,
		ip_address: str,
		health_check_id: str,
		ttl: int = 120,
	) -> None:
		"""Create or update the A record whose comment carries the identifier."""
		zone_id = self.create_zone(name)
		existing = [
			record
			for record in self.list_records(zone_id, "A", name)
			if record.get("comment") == identifier
		]
		payload = {
			"type": "A",
			"name": name,
			"content": ip_address,
			"ttl": ttl,
			"proxied": False,
			"comment": identifier,
		}
		if existing:
			self.client.request(
				"PUT", f"/zones/{zone_id}/dns_records/{existing[0]['id']}", payload=payload
			)
		else:
			self.client.request("POST", f"/zones/{zone_id}/dns_records", payload=payload)

	@override
	def remove_multivalue_a_record(
		self,
		name: str,
		identifier: str,
	) -> None:
		"""Remove every A record whose comment carries the identifier."""
		zone_id = self.create_zone(name)
		for record in self.list_records(zone_id, "A", name):
			if record.get("comment") == identifier:
				self.client.request("DELETE", f"/zones/{zone_id}/dns_records/{record['id']}")

	def zones(self) -> list[Mapping]:
		"""Return every zone of the account, one API page at a time."""
		zones: list[Mapping] = []
		for page in range(1, MAXIMUM_ZONE_PAGES + 1):
			result = self.client.request("GET", "/zones", {"per_page": ZONE_PAGE_SIZE, "page": page})
			if not isinstance(result, list):
				break
			zones += [zone for zone in result if isinstance(zone, Mapping)]
			if len(result) < ZONE_PAGE_SIZE:
				return zones
		return zones

	def list_records(self, zone_id: str, record_type: str, name: str) -> list[Mapping]:
		"""Return the zone records of one type and name."""
		result = self.client.request(
			"GET",
			f"/zones/{zone_id}/dns_records",
			{"type": record_type, "name": name, "per_page": 100},
		)
		if not isinstance(result, list):
			return []
		return [record for record in result if isinstance(record, Mapping) and record.get("id")]
