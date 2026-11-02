from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from frappe.tests import UnitTestCase

from atlas.atlas.core.dns_providers import get_dns_provider
from atlas.atlas.core.dns_providers.cloudflare import CloudflareError, CloudflareProvider


class TestCloudflareProvider(UnitTestCase):
	def test_the_provider_is_registered(self) -> None:
		provider = get_dns_provider("Cloudflare", self.settings())

		self.assertIsInstance(provider, CloudflareProvider)
		self.assertEqual(provider.credential_fields, ("cloudflare_api_token",))

	def test_validate_settings_refuses_a_bare_hostname(self) -> None:
		provider = self.provider(wildcard_domain="wardhive")

		with self.assertRaises(CloudflareError):
			provider.validate_settings()

	def test_upsert_record_creates_the_record_when_it_is_missing(self) -> None:
		provider = self.provider()
		provider.zones = Mock(return_value=[{"id": "zone-1", "name": "example.com"}])
		provider.client.request.return_value = []

		provider.upsert_record("A", "app.example.com", ["203.0.113.9"])

		self.assertEqual(
			provider.client.request.call_args_list[0].args,
			("GET", "/zones/zone-1/dns_records", {"type": "A", "name": "app.example.com", "per_page": 100}),
		)
		self.assertEqual(provider.client.request.call_args_list[1].args, ("POST", "/zones/zone-1/dns_records"))
		payload = provider.client.request.call_args_list[1].kwargs["payload"]
		self.assertEqual(payload["content"], "203.0.113.9")

	def test_upsert_record_updates_the_first_existing_record(self) -> None:
		provider = self.provider()
		provider.zones = Mock(return_value=[{"id": "zone-1", "name": "example.com"}])
		provider.client.request.return_value = [
			{"id": "record-1", "name": "app.example.com", "content": "203.0.113.1"}
		]

		provider.upsert_record("A", "app.example.com", ["203.0.113.9"])

		self.assertEqual(provider.client.request.call_args_list[1].args, ("PUT", "/zones/zone-1/dns_records/record-1"))

	def test_remove_record_deletes_every_matching_record(self) -> None:
		provider = self.provider()
		provider.zones = Mock(return_value=[{"id": "zone-1", "name": "example.com"}])
		provider.client.request.return_value = [
			{"id": "record-1", "name": "app.example.com"},
			{"id": "record-2", "name": "app.example.com"},
		]

		provider.remove_record("A", "app.example.com")

		self.assertEqual(len(provider.client.request.call_args_list), 3)
		self.assertEqual(
			provider.client.request.call_args_list[1].args,
			("DELETE", "/zones/zone-1/dns_records/record-1"),
		)

	def test_upsert_multivalue_a_record_keys_the_record_by_comment(self) -> None:
		provider = self.provider()
		provider.zones = Mock(return_value=[{"id": "zone-1", "name": "example.com"}])
		provider.client.request.return_value = [
			{"id": "record-1", "name": "proxy.example.com", "comment": "proxy-1"}
		]

		provider.upsert_multivalue_a_record("proxy.example.com", "proxy-1", "203.0.113.9", "check-1")

		self.assertEqual(
			provider.client.request.call_args_list[1].args,
			("PUT", "/zones/zone-1/dns_records/record-1"),
		)
		payload = provider.client.request.call_args_list[1].kwargs["payload"]
		self.assertEqual(payload["comment"], "proxy-1")

	def provider(self, wildcard_domain: str = "apps.example.com") -> CloudflareProvider:
		provider = object.__new__(CloudflareProvider)
		provider.settings = self.settings(wildcard_domain)
		provider.client = Mock()
		return provider

	@staticmethod
	def settings(wildcard_domain: str = "apps.example.com") -> SimpleNamespace:
		settings = SimpleNamespace(
			wildcard_domain=wildcard_domain,
			cloudflare_zone_id=None,
			is_dns_setup_completed=None,
		)
		settings.get_password = lambda field, **_: "token"
		settings.save = Mock()
		return settings
