from __future__ import annotations

import base64
import hmac
import logging
import re
from collections.abc import Mapping
from hashlib import md5, sha1
from itertools import count
from typing import TYPE_CHECKING, Any, ClassVar, override
from urllib.parse import quote, urlsplit

import requests

from atlas.atlas.core.server_providers import register
from atlas.atlas.core.server_providers.base import (
	ACCEPTED_OS_VERSIONS,
	ProviderOperationError,
	ProviderServer,
	ServerCreateRequest,
	ServerImageData,
	ServerPowerAction,
	ServerProvider,
	ServerSizeData,
)

if TYPE_CHECKING:
	from atlas.atlas.doctype.atlas_settings.atlas_settings import AtlasSettings
	from atlas.metal_server.doctype.metal_server.metal_server import MetalServer

logger = logging.getLogger("atlas.provider.cloudstack")

UBUNTU_TEMPLATE_OS = re.compile(r"^Ubuntu (\d\d\.\d\d)( LTS)?$")
DEBIAN_TEMPLATE_OS = re.compile(r"^Debian GNU/Linux (\d+)( \(64-bit\))?$")


class CloudStackError(ProviderOperationError):
	"""Raised when CloudStack rejects a provider request."""


class CloudStackClient:
	"""Send signed requests to the Apache CloudStack API."""

	page_size: ClassVar[int] = 500

	def __init__(self, endpoint: str, api_key: str, secret_key: str) -> None:
		"""Store the endpoint and open the shared request session."""
		self.endpoint = endpoint.rstrip("/")
		self.api_key = api_key
		self.secret_key = secret_key
		self.session = requests.Session()

	def request(
		self, command: str, params: Mapping[str, object] | None = None, *, allow_missing: bool = False
	) -> dict[str, Any]:
		"""Return the response payload of one signed command, or nothing for an allowed missing resource."""
		logger.info(
			"Provider request started",
			extra={"provider": "CloudStack", "operation": command, "resource": "/client/api"},
		)
		request_params = {**(params or {}), "response": "json"}
		try:
			response = self.session.get(
				f"{self.endpoint}/client/api",
				params=self.signed_query(command, request_params),
				timeout=30,
			)
		except requests.RequestException as error:
			logger.warning(
				"Provider request failed",
				extra={"provider": "CloudStack", "operation": command, "resource": "/client/api"},
			)
			raise CloudStackError(
				f"{command} could not reach CloudStack",
				code="provider_transport_error",
				is_retryable=True,
			) from error
		if allow_missing and response.status_code == 431:
			return {}
		if response.status_code >= 400:
			reason = self.error_text(response)
			logger.warning(
				"Provider request failed",
				extra={
					"provider": "CloudStack",
					"operation": command,
					"resource": "/client/api",
					"status": response.status_code,
				},
			)
			message = f"{command} failed with status {response.status_code}"
			if reason:
				message = f"{message}: {reason}"
			raise CloudStackError(
				message,
				code="provider_http_error",
				is_retryable=response.status_code == 429 or response.status_code >= 500,
			)
		result = response.json()
		if not isinstance(result, dict):
			raise CloudStackError(f"{command} returned a non-object JSON response")
		payload = result.get(f"{command.lower()}response")
		if not isinstance(payload, dict):
			raise CloudStackError(f"{command} returned no {command.lower()}response payload")
		return payload

	def paginate(
		self, command: str, list_key: str, params: Mapping[str, object] | None = None
	) -> list[Mapping]:
		"""Return every item under one key across all response pages."""
		items: list[Mapping] = []
		for page in count(1):
			response = self.request(command, {**(params or {}), "page": page, "pagesize": self.page_size})
			batch = response.get(list_key, [])
			if not isinstance(batch, list) or not all(isinstance(item, Mapping) for item in batch):
				raise CloudStackError(f"CloudStack response has invalid {list_key} entries")
			items.extend(batch)
			if len(batch) < self.page_size:
				return items

	def job_result(self, job_id: str) -> Mapping | None:
		"""Return one finished async job result, or None while the job is in progress."""
		result = self.request("queryAsyncJobResult", {"jobid": job_id})
		job_result = result.get("jobresult")
		if result.get("jobstatus") == 2:
			reason = job_result.get("errortext") if isinstance(job_result, Mapping) else None
			raise CloudStackError(f"CloudStack job {job_id} failed: {reason or 'unknown reason'}")
		if result.get("jobstatus") == 1 and isinstance(job_result, Mapping):
			return job_result
		return None

	def signed_query(self, command: str, params: Mapping[str, object] | None) -> str:
		"""Return the query string with the API key and the official request signature."""
		parameters = dict(params or {})
		parameters["command"] = command
		parameters["apiKey"] = self.api_key
		query = self.canonical_query(parameters)
		return f"{query}&signature={quote(self.signature(query, self.secret_key), safe='')}"

	@staticmethod
	def canonical_query(parameters: Mapping[str, object]) -> str:
		"""Return the sorted, URL-encoded query that CloudStack signs."""
		return "&".join(
			f"{quote(str(key), safe='')}={quote(str(value), safe='')}"
			for key, value in sorted(parameters.items(), key=lambda item: item[0].lower())
		)

	@staticmethod
	def signature(query: str, secret_key: str) -> str:
		"""Sign the lowercased canonical query with HMAC-SHA1, as the CloudStack API requires."""
		digest = hmac.new(secret_key.encode(), query.lower().encode(), sha1).digest()
		return base64.b64encode(digest).decode()

	@staticmethod
	def error_text(response: requests.Response) -> str:
		"""Return the errortext of one CloudStack error response, or an empty string."""
		try:
			result = response.json()
		except ValueError:
			return ""
		for payload in result.values() if isinstance(result, dict) else ():
			if isinstance(payload, Mapping) and isinstance(payload.get("errortext"), str):
				return payload["errortext"]
		return ""


DEFAULT_POOL_VOLUME_SIZE_GIB = 40


@register
class CloudStackProvider(ServerProvider):
	"""Provide Atlas server operations through the Apache CloudStack API.

	CloudStack assigns one network interface with both addresses at deployment,
	so Atlas uses it for the mesh and the public traffic.
	"""

	provider_type = "CloudStack"
	credential_fields = ("cloudstack_api_endpoint", "cloudstack_api_key", "cloudstack_secret_key")
	error_class = CloudStackError

	server_status_map: ClassVar[dict[str, str]] = {
		"Starting": "Installing",
		"Running": "Installing",
		"Migrating": "Installing",
		"Stopping": "Stopped",
		"Stopped": "Stopped",
		"Destroyed": "Deleted",
		"Expunging": "Deleted",
		"Error": "Failed",
	}

	def __init__(self, settings: "AtlasSettings | None" = None) -> None:
		super().__init__(settings)
		self.client = CloudStackClient(
			self.settings.cloudstack_api_endpoint,
			self.settings.cloudstack_api_key,
			self.settings.get_password("cloudstack_secret_key", raise_exception=False) or "",
		)

	@override
	def validate_settings(self) -> None:
		"""Validate the CloudStack endpoint and zone."""
		parts = urlsplit(self.settings.cloudstack_api_endpoint)
		if parts.scheme not in {"http", "https"} or not parts.hostname:
			raise CloudStackError(
				f"CloudStack API endpoint {self.settings.cloudstack_api_endpoint!r} is not an HTTP URL"
			)
		if not self.settings.cloudstack_zone:
			raise CloudStackError("Atlas Settings has no CloudStack zone")

	@override
	def setup_infrastructure(self) -> None:
		"""Check the zone and register the Atlas Secure Shell key pair."""
		self.zone_id()
		self.ensure_ssh_key_pair()
		self.settings.is_server_provider_setup_completed = 1
		self.settings.save()

	@override
	def validate_credentials(self) -> bool:
		"""Return true when the CloudStack keys can list zones."""
		self.client.request("listZones")
		return True

	@override
	def fetch_server_sizes(self) -> tuple[ServerSizeData, ...]:
		"""Return the fixed-size compute offerings the CloudStack account can use."""
		offerings = self.client.paginate("listServiceOfferings", "serviceoffering")
		return tuple(size for offering in offerings if (size := self.server_size(offering)) is not None)

	@override
	def fetch_server_images(self) -> tuple[ServerImageData, ...]:
		"""Return the executable templates for the operating systems Atlas accepts."""
		templates = self.client.paginate("listTemplates", "template", {"templatefilter": "executable"})
		return tuple(image for template in templates if (image := self.server_image(template)) is not None)

	@staticmethod
	def cloudstack_name(atlas_name: str) -> str:
		"""Return the CloudStack name for an Atlas resource name.

		CloudStack names cannot start with a digit, and Atlas names are UUIDs."""
		return f"atlas-{atlas_name}"

	@override
	def ensure_server(self, request: ServerCreateRequest) -> ProviderServer:
		"""Return the CloudStack server for the Atlas name, deploying it when absent."""
		remote_server = self.find_server(request.name)
		if remote_server is None:
			remote_server = self.deploy_server(request)
		self.ensure_pool_volume(request, remote_server)
		return self.to_provider_server(remote_server)

	@override
	def prepare_server(self, server: "MetalServer") -> None:
		"""Apply the addresses CloudStack assigned at deployment."""
		if not server.provider_server_id:
			raise CloudStackError("Atlas server has no CloudStack server ID")

		remote_server = self.fetch_server(server.provider_server_id)
		self.apply_provider_server(server, self.to_provider_server(remote_server))
		address = self.nic_ipv4_address(remote_server)
		if address is None:
			raise CloudStackError(f"CloudStack server {server.provider_server_id} has no IPv4 address")
		server.private_ipv4_address = address

	@override
	def configure_server_network(self, server: "MetalServer") -> None:
		"""Use the default route interface for the mesh and the public traffic."""
		device = self.uplink_device(server)
		server.public_network_interface = device
		server.private_network_interface = device
		self.wait_for_private_address(server)

	@override
	def storage_pool_device(self, server: "MetalServer") -> str:
		"""Return the virtio data disk that carries the virtual machine storage pool."""
		return "/dev/vdb"

	@override
	def set_power_state(self, provider_server_id: str, action: ServerPowerAction) -> None:
		"""Apply one power action to a CloudStack server."""
		job = self.client.request(f"{action.value}VirtualMachine", {"id": provider_server_id})
		job_id = job.get("jobid")
		if isinstance(job_id, str):
			self.wait_for_job(job_id, f"the {action.value} of CloudStack server {provider_server_id}")

	@override
	def delete_server(self, provider_server_id: str, _provider_metadata: Mapping[str, object]) -> None:
		"""Destroy and expunge one CloudStack server if it exists."""
		destroyed = self.client.request(
			"destroyVirtualMachine", {"id": provider_server_id}, allow_missing=True
		)
		job_id = destroyed.get("jobid")
		if isinstance(job_id, str):
			self.wait_for_job(job_id, f"the destruction of CloudStack server {provider_server_id}")

		expunged = self.client.request(
			"expungeVirtualMachine", {"id": provider_server_id}, allow_missing=True
		)
		job_id = expunged.get("jobid")
		if isinstance(job_id, str):
			self.wait_for_job(job_id, f"the expunge of CloudStack server {provider_server_id}")

	def zone_id(self) -> str:
		"""Return the ID of the configured CloudStack zone."""
		zones = self.client.paginate("listZones", "zone")
		ids = [
			zone["id"]
			for zone in zones
			if zone.get("name") == self.settings.cloudstack_zone and isinstance(zone.get("id"), str)
		]
		if len(ids) != 1:
			raise CloudStackError(f"CloudStack has no unique zone named {self.settings.cloudstack_zone!r}")
		return ids[0]

	def network_id(self) -> str:
		"""Return the guest network of the zone that servers deploy into.

		An advanced zone deploys no default network, so the guest network must exist."""
		networks = self.client.paginate("listNetworks", "network", {"zoneid": self.zone_id()})
		ids = [
			network["id"]
			for network in networks
			if network.get("state") == "Implemented" and isinstance(network.get("id"), str)
		]
		if len(ids) != 1:
			raise CloudStackError("CloudStack has no unique implemented guest network for the zone")
		return ids[0]

	def root_ssh_user_data(self) -> str:
		"""Return the cloud-init user data that grants Atlas root SSH access.

		Provider templates may not inject the deploy key pair into the root
		account, and the host installation needs it."""
		return "\n".join([
			"#cloud-config",
			"disable_root: false",
			"ssh_authorized_keys:",
			f"  - {self.settings.public_ssh_key}",
		])

	def disk_offering_request(self, size_gib: int) -> Mapping[str, object]:
		"""Return the createVolume disk parameters for one pool size.

		An advanced zone requires a disk offering; a customized one carries the size,
		a fixed one must already be large enough for the pool."""
		offerings = self.client.paginate("listDiskOfferings", "diskoffering", {"zoneid": self.zone_id()})
		active = [
			offering
			for offering in offerings
			if offering.get("state") == "Active" and isinstance(offering.get("id"), str)
		]
		for offering in active:
			if offering.get("iscustomized"):
				return {"diskofferingid": offering["id"], "size": size_gib}
		for offering in active:
			if isinstance(offering.get("disksize"), int) and offering["disksize"] >= size_gib:
				return {"diskofferingid": offering["id"]}
		raise CloudStackError(f"CloudStack has no disk offering for a {size_gib} GiB pool volume")

	def ensure_ssh_key_pair(self) -> None:
		"""Register the Atlas public key as a CloudStack key pair when absent.

		CloudStack rejects a second registration of one public key, so a pair that
		another operator registered earlier stays in place under its own name.
		"""
		if self.registered_key_pair_name():
			return
		self.client.request(
			"registerSSHKeyPair",
			{"name": self.fallback_key_pair_name, "publickey": self.settings.public_ssh_key},
		)

	def registered_key_pair_name(self) -> str | None:
		"""Return the name of the account key pair that carries the Atlas public key."""
		fingerprint = self.public_key_fingerprint
		for key_pair in self.client.paginate("listSSHKeyPairs", "sshkeypair"):
			if key_pair.get("fingerprint") == fingerprint and isinstance(key_pair.get("name"), str):
				return key_pair["name"]
		return None

	@property
	def ssh_key_pair_name(self) -> str:
		"""Return the CloudStack key pair name that carries the Atlas public key."""
		return self.registered_key_pair_name() or self.fallback_key_pair_name

	@property
	def fallback_key_pair_name(self) -> str:
		"""Return the CloudStack key pair name Atlas registers when the key is absent."""
		return f"atlas-{self.settings.region_name}-ssh-key"

	@property
	def public_key_fingerprint(self) -> str:
		"""Return the MD5 fingerprint CloudStack reports for the Atlas public key."""
		fields = self.settings.public_ssh_key.split()
		if len(fields) < 2:
			raise CloudStackError("Atlas Settings has no usable public SSH key")
		digest = md5(base64.b64decode(fields[1])).hexdigest()
		return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))

	def wait_for_job(self, job_id: str, description: str) -> Mapping:
		"""Wait for one CloudStack async job and return its result."""
		return self.poll(
			lambda: self.client.job_result(job_id),
			timeout_seconds=self.setup_poll_timeout_seconds,
			poll_interval_seconds=self.setup_poll_interval_seconds,
			description=description,
		)

	def find_server(self, name: str) -> Mapping | None:
		"""Return the CloudStack server with the Atlas name."""
		matches = self.client.paginate(
			"listVirtualMachines", "virtualmachine", {"name": self.cloudstack_name(name)}
		)
		if len(matches) > 1:
			raise CloudStackError(f"CloudStack returned multiple servers for Atlas server {name}")
		return matches[0] if matches else None

	def fetch_server(self, provider_server_id: str) -> Mapping:
		"""Return one CloudStack server by ID."""
		matches = self.client.paginate("listVirtualMachines", "virtualmachine", {"id": provider_server_id})
		if len(matches) != 1:
			raise CloudStackError(f"CloudStack has no server {provider_server_id}")
		return matches[0]

	def deploy_server(self, request: ServerCreateRequest) -> Mapping:
		"""Deploy one CloudStack server from an Atlas request."""
		offering_id = request.size_provider_metadata.get("id")
		template_id = request.image_provider_metadata.get("id")
		if not isinstance(offering_id, str):
			raise CloudStackError(f"Metal Server Size {request.server_size} has no CloudStack offering ID")
		if not isinstance(template_id, str):
			raise CloudStackError(f"Metal Server Image {request.server_image} has no CloudStack template ID")

		deployment = self.client.request(
			"deployVirtualMachine",
			{
				"serviceofferingid": offering_id,
				"templateid": template_id,
				"zoneid": self.zone_id(),
				"networkids": self.network_id(),
				"name": self.cloudstack_name(request.name),
				"displayname": self.cloudstack_name(request.name),
				"keypair": self.ssh_key_pair_name,
				"userdata": base64.b64encode(self.root_ssh_user_data().encode()).decode(),
			},
		)
		job_id = deployment.get("jobid")
		if not isinstance(job_id, str):
			raise CloudStackError(f"CloudStack did not return a deployment job for server {request.name}")
		result = self.wait_for_job(job_id, f"the deployment of CloudStack server {request.name}")
		remote_server = result.get("virtualmachine")
		if not isinstance(remote_server, Mapping):
			raise CloudStackError(f"CloudStack job {job_id} has no deployed server")
		return remote_server

	def ensure_pool_volume(self, request: ServerCreateRequest, remote_server: Mapping) -> None:
		"""Attach the data volume that carries the virtual machine storage pool.

		The volume size follows the compute offering root disk, with a
		100 GiB fallback for offerings that leave the disk to the template.
		"""
		server_id = remote_server.get("id")
		if not isinstance(server_id, str):
			raise CloudStackError(f"CloudStack server {request.name} has no ID")

		name = f"{self.cloudstack_name(request.name)}-pool"
		for volume in self.client.paginate("listVolumes", "volume", {"name": name}):
			if volume.get("virtualmachineid") == server_id:
				return
			if volume.get("virtualmachineid"):
				raise CloudStackError(f"CloudStack pool volume {name} is attached to another server")
			self.attach_volume(volume, server_id, name)
			return

		size_gib = request.size_provider_metadata.get("rootdisksize")
		if not isinstance(size_gib, int) or size_gib <= 0:
			size_gib = DEFAULT_POOL_VOLUME_SIZE_GIB
		created = self.client.request(
			"createVolume",
			{"name": name, "zoneid": self.zone_id(), **self.disk_offering_request(size_gib)},
		)
		job_id = created.get("jobid")
		if not isinstance(job_id, str):
			raise CloudStackError(f"CloudStack did not return a creation job for pool volume {name}")
		result = self.wait_for_job(job_id, f"the creation of pool volume {name}")
		volume = result.get("volume")
		if not isinstance(volume, Mapping):
			raise CloudStackError(f"CloudStack job {job_id} has no created pool volume {name}")
		self.attach_volume(volume, server_id, name)

	def attach_volume(self, volume: Mapping, server_id: str, name: str) -> None:
		"""Attach one detached CloudStack volume and wait for the job."""
		attached = self.client.request(
			"attachVolume", {"id": volume.get("id"), "virtualmachineid": server_id}
		)
		job_id = attached.get("jobid")
		if isinstance(job_id, str):
			self.wait_for_job(job_id, f"the attach of pool volume {name}")

	def uplink_device(self, server: "MetalServer") -> str:
		"""Return the guest device name that carries the CloudStack default route."""
		from atlas.atlas.core.ssh import SSHRunner

		result = SSHRunner(server.ssh_host).run_command("ip -4 -o route show default", timeout_seconds=15)
		fields = result.output.split()
		if result.exit_code != 0 or "dev" not in fields:
			raise CloudStackError(f"Atlas server {server.name} has no default route device")
		return fields[fields.index("dev") + 1]

	def server_size(self, offering: Mapping) -> ServerSizeData | None:
		"""Convert one CloudStack compute offering into Atlas catalog data.

		Return None for a custom offering: it leaves the CPU count and the memory to
		the user at deployment time, so it describes no fixed catalog size. CloudStack
		reports no per-offering architecture, and Atlas host templates are x86_64.
		"""
		name = offering.get("name")
		cpu_count = offering.get("cpunumber")
		memory_mib = offering.get("memory")
		if not isinstance(name, str) or not isinstance(cpu_count, int) or not isinstance(memory_mib, int):
			return None

		disk_gib = offering.get("rootdisksize")
		return ServerSizeData(
			name=name,
			architecture="amd64",
			cpu_count=cpu_count,
			memory_mib=memory_mib,
			disk_gib=disk_gib if isinstance(disk_gib, int) else 0,
			hourly_pricing_usd_cents=None,
			monthly_pricing_usd_cents=None,
			provider_metadata=dict(offering),
		)

	def server_image(self, template: Mapping) -> ServerImageData | None:
		"""Convert one CloudStack template into Atlas catalog data, or None for another OS."""
		os_type = template.get("ostypename")
		if not isinstance(os_type, str):
			return None

		match = UBUNTU_TEMPLATE_OS.match(os_type)
		os_name = "Ubuntu"
		if match is None:
			match = DEBIAN_TEMPLATE_OS.match(os_type)
			os_name = "Debian"
		if match is None:
			return None

		version = match.group(1)
		if version not in ACCEPTED_OS_VERSIONS[os_name]:
			return None
		return ServerImageData(
			name=f"{os_name}_{version}", os=os_name, version=version, provider_metadata=dict(template)
		)

	@classmethod
	def to_provider_server(cls, remote_server: Mapping) -> ProviderServer:
		"""Convert one CloudStack response to provider-neutral data."""
		provider_server_id = remote_server.get("id")
		if not isinstance(provider_server_id, str):
			raise CloudStackError("CloudStack did not return a server ID")

		return ProviderServer(
			provider_server_id=provider_server_id,
			status=cls.server_status_map.get(remote_server.get("state")),
			public_ipv4_address=cls.nic_ipv4_address(remote_server),
			provider_metadata={"server": dict(remote_server)},
		)

	@staticmethod
	def nic_ipv4_address(remote_server: Mapping) -> str | None:
		"""Return the IPv4 address of the first CloudStack network interface."""
		nics = remote_server.get("nic")
		if not isinstance(nics, list):
			return None
		for nic in nics:
			if isinstance(nic, Mapping) and isinstance(nic.get("ipaddress"), str):
				return nic["ipaddress"]
		return None
