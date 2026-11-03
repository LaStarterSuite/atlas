from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

from frappe.tests import UnitTestCase

from atlas.atlas.core.server_providers.base import (
	ServerCreateRequest,
	ServerPowerAction,
	UnsupportedProviderOperation,
)
from atlas.atlas.core.server_providers.cloudstack import CloudStackError, CloudStackProvider
from atlas.atlas.core.server_providers.cloudstack.provider import CloudStackClient
from atlas.atlas.core.server_providers.registry import get_server_provider

SERVER_NAME = "01a0c05f-e209-70ad-a183-dda2a727cd8b"


def api_response(status_code: int, payload: dict) -> Mock:
	response = Mock(status_code=status_code)
	response.json.return_value = payload
	return response


class TestCloudStackClient(UnitTestCase):
	def client(self, status_code: int = 200, payload: dict | None = None) -> CloudStackClient:
		client = CloudStackClient("https://cloudstack.example.com/", "ApiKey", "SecretKey==")
		client.session = Mock()
		client.session.get.return_value = api_response(status_code, payload or {})
		return client

	def test_the_signed_query_follows_the_official_algorithm(self) -> None:
		query = CloudStackClient("https://cloudstack.example.com", "ApiKey", "SecretKey==").signed_query(
			"listVirtualMachines", {"name": "atlas host 01"}
		)

		self.assertEqual(
			query,
			"apiKey=ApiKey&command=listVirtualMachines&name=atlas%20host%2001"
			"&signature=dRMKjzsYynC5p8cciMy0ilFP9T8%3D",
		)

	def test_request_sends_the_signed_query_and_returns_the_payload(self) -> None:
		client = self.client(payload={"listzonesresponse": {"zone": [{"id": "zone-id"}]}})

		result = client.request("listZones")

		self.assertEqual(result, {"zone": [{"id": "zone-id"}]})
		self.assertEqual(client.session.get.call_args.args, ("https://cloudstack.example.com/client/api",))
		self.assertEqual(
			client.session.get.call_args.kwargs["params"],
			client.signed_query("listZones", {"response": "json"}),
		)

	def test_request_treats_431_as_an_allowed_missing_resource(self) -> None:
		client = self.client(
			431,
			{
				"destroyvirtualmachineresponse": {
					"errorcode": 431,
					"errortext": "Unable to find a virtual machine",
				}
			},
		)

		self.assertEqual(client.request("destroyVirtualMachine", {"id": "vm-1"}, allow_missing=True), {})

	def test_request_raises_for_an_unsuccessful_response(self) -> None:
		client = self.client(500, {"errorresponse": {"errortext": "internal error"}})

		with self.assertRaises(CloudStackError) as raised:
			client.request("listZones")

		self.assertEqual(raised.exception.code, "provider_http_error")
		self.assertTrue(raised.exception.is_retryable)
		self.assertIn("internal error", str(raised.exception))

	def test_job_result_returns_the_result_when_the_job_succeeded(self) -> None:
		client = self.client(
			payload={
				"queryasyncjobresultresponse": {
					"jobstatus": 1,
					"jobresult": {"virtualmachine": {"id": "vm-1"}},
				}
			}
		)

		self.assertEqual(client.job_result("job-1"), {"virtualmachine": {"id": "vm-1"}})

	def test_job_result_returns_none_while_the_job_is_in_progress(self) -> None:
		client = self.client(payload={"queryasyncjobresultresponse": {"jobstatus": 0}})

		self.assertIsNone(client.job_result("job-1"))

	def test_job_result_raises_a_permanent_error_for_a_failed_job(self) -> None:
		client = self.client(
			payload={
				"queryasyncjobresultresponse": {
					"jobstatus": 2,
					"jobresult": {"errortext": "insufficient capacity"},
				}
			}
		)

		with self.assertRaises(CloudStackError) as raised:
			client.job_result("job-1")

		self.assertFalse(raised.exception.is_retryable)
		self.assertIn("insufficient capacity", str(raised.exception))

	def test_paginate_collects_every_page(self) -> None:
		client = self.client()
		client.page_size = 2
		client.session.get.side_effect = [
			api_response(
				200, {"listserviceofferingsresponse": {"serviceoffering": [{"id": "1"}, {"id": "2"}]}}
			),
			api_response(200, {"listserviceofferingsresponse": {"serviceoffering": [{"id": "3"}]}}),
		]

		items = client.paginate("listServiceOfferings", "serviceoffering")

		self.assertEqual([item["id"] for item in items], ["1", "2", "3"])


class TestCloudStackProvider(UnitTestCase):
	def test_the_provider_is_registered(self) -> None:
		provider = get_server_provider("CloudStack", self.settings())

		self.assertIsInstance(provider, CloudStackProvider)
		self.assertEqual(
			provider.credential_fields,
			("cloudstack_api_endpoint", "cloudstack_api_key", "cloudstack_secret_key"),
		)

	def test_setup_infrastructure_checks_the_zone_and_registers_the_key_pair(self) -> None:
		provider = self.provider()
		provider.client.paginate.side_effect = [[{"id": "zone-id", "name": "zone-1"}], []]

		provider.setup_infrastructure()

		provider.client.request.assert_called_once_with(
			"registerSSHKeyPair", {"name": "atlas-par-1-ssh-key", "publickey": "ssh-ed25519 AAAA"}
		)
		self.assertEqual(provider.settings.is_server_provider_setup_completed, 1)
		provider.settings.save.assert_called_once_with()

	def test_setup_infrastructure_reuses_a_registered_key_pair(self) -> None:
		provider = self.provider()
		provider.client.paginate.side_effect = [
			[{"id": "zone-id", "name": "zone-1"}],
			[{"name": "wardhive-matrix", "fingerprint": provider.public_key_fingerprint}],
		]

		provider.setup_infrastructure()

		provider.client.request.assert_not_called()
		self.assertEqual(provider.settings.is_server_provider_setup_completed, 1)
		provider.settings.save.assert_called_once_with()

	def test_ssh_key_pair_name_reuses_the_registered_pair(self) -> None:
		provider = self.provider()
		provider.client.paginate.return_value = [{"name": "wardhive-matrix", "fingerprint": "aa:bb:cc:dd"}]

		self.assertEqual(provider.ssh_key_pair_name, "atlas-par-1-ssh-key")

		provider.client.paginate.return_value = [
			{"name": "wardhive-matrix", "fingerprint": provider.public_key_fingerprint}
		]

		self.assertEqual(provider.ssh_key_pair_name, "wardhive-matrix")

	def test_validate_settings_refuses_a_bare_hostname(self) -> None:
		provider = self.provider()
		provider.settings.cloudstack_api_endpoint = "cloudstack.example.com"

		with self.assertRaises(CloudStackError):
			provider.validate_settings()

	def test_zone_id_resolves_the_configured_zone_name(self) -> None:
		provider = self.provider()
		provider.client.paginate.return_value = [
			{"id": "zone-id", "name": "zone-1"},
			{"id": "other", "name": "zone-2"},
		]

		self.assertEqual(provider.zone_id(), "zone-id")

	def test_fetch_server_sizes_converts_compute_offerings(self) -> None:
		provider = self.provider()
		provider.client.paginate.return_value = [
			{"id": "offering-1", "name": "4vCPU 8GB", "cpunumber": 4, "memory": 8192, "rootdisksize": 0}
		]

		sizes = provider.fetch_server_sizes()

		self.assertEqual(
			(
				sizes[0].name,
				sizes[0].architecture,
				sizes[0].cpu_count,
				sizes[0].memory_mib,
				sizes[0].disk_gib,
			),
			("4vCPU 8GB", "amd64", 4, 8192, 0),
		)
		self.assertIsNone(sizes[0].hourly_pricing_usd_cents)
		self.assertEqual(sizes[0].provider_metadata["id"], "offering-1")
		provider.client.paginate.assert_called_once_with("listServiceOfferings", "serviceoffering")

	def test_fetch_server_sizes_skips_custom_offerings(self) -> None:
		provider = self.provider()
		provider.client.paginate.return_value = [
			{"id": "custom", "name": "Unconstrained compute offering", "rootdisksize": 0},
			{"id": "offering-1", "name": "m1.small", "cpunumber": 1, "memory": 1024, "rootdisksize": 0},
		]

		sizes = provider.fetch_server_sizes()

		self.assertEqual([size.name for size in sizes], ["m1.small"])

	def test_fetch_server_images_keeps_supported_templates(self) -> None:
		provider = self.provider()
		provider.client.paginate.return_value = [
			{"id": "template-1", "ostypename": "Ubuntu 24.04 LTS"},
			{"id": "template-2", "ostypename": "Debian GNU/Linux 12 (64-bit)"},
			{"id": "template-3", "ostypename": "CentOS 7"},
		]

		images = provider.fetch_server_images()

		self.assertEqual(
			[(image.name, image.os, image.version) for image in images],
			[("Ubuntu_24.04", "Ubuntu", "24.04"), ("Debian_12", "Debian", "12")],
		)
		provider.client.paginate.assert_called_once_with(
			"listTemplates", "template", {"templatefilter": "executable"}
		)

	def test_ensure_server_deploys_and_waits_for_the_async_job(self) -> None:
		provider = self.provider()
		provider.zone_id = Mock(return_value="zone-id")
		provider.network_id = Mock(return_value="net-1")
		provider.find_server = Mock(return_value=None)
		provider.client.paginate.return_value = []
		provider.client.request.side_effect = [
			{"id": "vm-1", "jobid": "job-1"},
			{"jobid": "job-2"},
			{"jobid": "job-3"},
		]
		provider.client.job_result.side_effect = [
			None,
			{
				"virtualmachine": {
					"id": "vm-1",
					"state": "Running",
					"nic": [{"ipaddress": "203.0.113.9"}],
				}
			},
			{"volume": {"id": "vol-1", "name": f"{SERVER_NAME}-pool"}},
			{"volume": {"id": "vol-1", "name": f"{SERVER_NAME}-pool"}},
		]

		with patch("atlas.atlas.core.server_providers.base.sleep"):
			server = provider.ensure_server(self.request())

		self.assertEqual(
			provider.client.request.call_args_list[0].args,
			(
				"deployVirtualMachine",
				{
					"serviceofferingid": "offering-1",
					"templateid": "template-1",
					"zoneid": "zone-id",
					"networkids": "net-1",
					"name": f"atlas-{SERVER_NAME}",
					"displayname": f"atlas-{SERVER_NAME}",
					"keypair": "atlas-par-1-ssh-key",
				},
			),
		)
		self.assertEqual((server.provider_server_id, server.status), ("vm-1", "Installing"))
		self.assertEqual(server.public_ipv4_address, "203.0.113.9")

	def test_ensure_server_reuses_the_server_with_the_atlas_name(self) -> None:
		provider = self.provider()
		provider.find_server = Mock(return_value={"id": "vm-1", "state": "Stopped", "nic": []})
		provider.client.paginate.return_value = [{"id": "vol-1", "virtualmachineid": "vm-1"}]

		server = provider.ensure_server(self.request())

		self.assertEqual((server.provider_server_id, server.status), ("vm-1", "Stopped"))
		provider.client.request.assert_not_called()

	def test_ensure_server_creates_and_attaches_the_pool_volume(self) -> None:
		provider = self.provider()
		provider.zone_id = Mock(return_value="zone-id")
		provider.find_server = Mock(return_value={"id": "vm-1", "state": "Running", "nic": []})
		provider.client.paginate.return_value = []
		provider.client.request.side_effect = [{"jobid": "job-1"}, {"jobid": "job-2"}]
		provider.client.job_result.side_effect = [
			{"volume": {"id": "vol-1", "name": f"{SERVER_NAME}-pool"}},
			{"success": True},
		]

		provider.ensure_server(self.request())

		self.assertEqual(
			provider.client.request.call_args_list[0].args,
			("createVolume", {"name": f"atlas-{SERVER_NAME}-pool", "size": 100, "zoneid": "zone-id"}),
		)
		self.assertEqual(
			provider.client.request.call_args_list[1].args,
			("attachVolume", {"id": "vol-1", "virtualmachineid": "vm-1"}),
		)

	def test_ensure_server_attaches_a_detached_pool_volume(self) -> None:
		provider = self.provider()
		provider.find_server = Mock(return_value={"id": "vm-1", "state": "Stopped", "nic": []})
		provider.client.paginate.return_value = [{"id": "vol-1", "virtualmachineid": None}]
		provider.client.request.side_effect = [{"jobid": "job-1"}]
		provider.client.job_result.side_effect = [{"success": True}]

		provider.ensure_server(self.request())

		self.assertEqual(
			provider.client.request.call_args_list[0].args,
			("attachVolume", {"id": "vol-1", "virtualmachineid": "vm-1"}),
		)

	def test_ensure_server_refuses_a_pool_volume_of_another_server(self) -> None:
		provider = self.provider()
		provider.find_server = Mock(return_value={"id": "vm-1", "state": "Stopped", "nic": []})
		provider.client.paginate.return_value = [{"id": "vol-1", "virtualmachineid": "vm-9"}]

		with self.assertRaises(CloudStackError):
			provider.ensure_server(self.request())

	def test_find_server_refuses_an_ambiguous_name(self) -> None:
		provider = self.provider()
		provider.client.paginate.return_value = [{"id": "vm-1"}, {"id": "vm-2"}]

		with self.assertRaises(CloudStackError):
			provider.find_server(SERVER_NAME)

	def test_prepare_server_applies_the_deployed_addresses(self) -> None:
		provider = self.provider()
		provider.client.paginate.return_value = [
			{"id": "vm-1", "state": "Running", "nic": [{"ipaddress": "198.51.100.7"}]}
		]
		server = SimpleNamespace(
			provider_server_id="vm-1",
			provider_metadata=None,
			status=None,
			public_ipv4_address=None,
			private_ipv4_address=None,
		)

		provider.prepare_server(server)

		self.assertEqual(
			(server.public_ipv4_address, server.private_ipv4_address), ("198.51.100.7", "198.51.100.7")
		)

	def test_configure_server_network_uses_the_default_route_device(self) -> None:
		provider = self.provider()
		server = SimpleNamespace(
			name=SERVER_NAME,
			ssh_host="198.51.100.7",
			provider_metadata=None,
			public_network_interface=None,
			private_network_interface=None,
			private_ipv4_address="198.51.100.7",
		)
		runner = Mock()
		runner.run_command.return_value = SimpleNamespace(
			exit_code=0, output="default via 198.51.100.1 dev eth0\n"
		)
		provider.wait_for_private_address = Mock()

		with patch("atlas.atlas.core.ssh.SSHRunner", return_value=runner):
			provider.configure_server_network(server)

		self.assertEqual(
			(server.public_network_interface, server.private_network_interface), ("eth0", "eth0")
		)
		provider.wait_for_private_address.assert_called_once_with(server)

	def test_set_power_state_sends_the_command_and_waits_for_the_job(self) -> None:
		provider = self.provider()
		provider.client.request.side_effect = [{"jobid": "job-1"}]
		provider.client.job_result.return_value = {"virtualmachine": {"id": "vm-1"}}

		with patch("atlas.atlas.core.server_providers.base.sleep"):
			provider.set_power_state("vm-1", ServerPowerAction.START)

		self.assertEqual(
			provider.client.request.call_args_list[0].args, ("startVirtualMachine", {"id": "vm-1"})
		)

	def test_a_failed_job_fails_the_wait_without_a_retry(self) -> None:
		provider = self.provider()
		provider.client.job_result = Mock(
			side_effect=CloudStackError("CloudStack job job-1 failed: insufficient capacity")
		)

		with self.assertRaises(CloudStackError) as raised:
			provider.wait_for_job("job-1", "the deployment")

		self.assertFalse(raised.exception.is_retryable)
		provider.client.job_result.assert_called_once_with("job-1")

	def test_delete_server_destroys_and_expunges(self) -> None:
		provider = self.provider()
		provider.client.request.side_effect = [{"jobid": "job-1"}, {"jobid": "job-2"}]
		provider.client.job_result.return_value = {}

		with patch("atlas.atlas.core.server_providers.base.sleep"):
			provider.delete_server("vm-1", {})

		self.assertEqual(
			[call.args[0] for call in provider.client.request.call_args_list],
			["destroyVirtualMachine", "expungeVirtualMachine"],
		)
		self.assertTrue(provider.client.request.call_args_list[0].kwargs["allow_missing"])
		self.assertTrue(provider.client.request.call_args_list[1].kwargs["allow_missing"])

	def test_delete_server_skips_a_missing_server(self) -> None:
		provider = self.provider()
		provider.client.request.side_effect = [{}, {}]
		provider.wait_for_job = Mock()

		provider.delete_server("vm-1", {})

		provider.wait_for_job.assert_not_called()

	def test_optional_address_operations_are_refused(self) -> None:
		provider = self.provider()

		with self.assertRaises(UnsupportedProviderOperation):
			provider.reserve_public_ip_address(4)

	def provider(self) -> CloudStackProvider:
		provider = object.__new__(CloudStackProvider)
		provider.settings = self.settings()
		provider.client = Mock()
		return provider

	@staticmethod
	def settings() -> SimpleNamespace:
		settings = SimpleNamespace(
			cloudstack_api_endpoint="https://cloudstack.example.com",
			cloudstack_api_key="api-key",
			cloudstack_zone="zone-1",
			region_name="par-1",
			public_ssh_key="ssh-ed25519 AAAA",
			is_server_provider_setup_completed=None,
		)
		settings.get_password = lambda field, **_: "secret-key"
		settings.save = Mock()
		return settings

	@staticmethod
	def request() -> ServerCreateRequest:
		return ServerCreateRequest(
			name=SERVER_NAME,
			server_size="4vCPU 8GB",
			server_image="Ubuntu_24.04",
			size_provider_metadata={"id": "offering-1"},
			image_provider_metadata={"id": "template-1"},
		)
