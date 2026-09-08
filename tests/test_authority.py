
import os

import struct
import unittest
from unittest import mock
from public_edge_manager import authority


os.environ.setdefault("CANDIDATES_JSON", "[]")


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        authority.SERVICE_DEFINITIONS = {
            "app.example.com.": {"service": "app", "class": "web", "probePath": "/healthz"}
        }
        authority.SERVICES = {"app.example.com.": "app"}
        authority.HEALTH = {"app": {}}
        authority.CANDIDATES[:] = []
        authority.FABRIC_ASSESSMENTS.clear()
        authority.FABRIC_API_AVAILABLE = False
        authority.FABRIC_EVIDENCE_MODE = "Disabled"
        authority.FABRIC_EVIDENCE_ALLOWED_STATES = {"Ready", "Partial"}
        authority.FABRIC_EVIDENCE_MIN_CONFIDENCE = 0
        authority.FABRIC_EVIDENCE_WEIGHTS = {}

    @staticmethod
    def assessment(node="edge-node", state="Ready", valid_until="2099-01-01T00:00:00Z",
                   condition_status="True"):
        return {
            "metadata": {"name": f"node-{node}"},
            "spec": {
                "subjectRef": {"apiVersion": "v1", "kind": "Node", "name": node},
                "scope": {"plane": "host-and-pod", "direction": "bidirectional", "protocol": "mixed"},
            },
            "status": {
                "state": state,
                "observedAt": "2026-09-08T00:00:00Z",
                "validUntil": valid_until,
                "dimensions": {"optimality": .8, "stability": .7, "independence": None},
                "confidence": {"optimality": .9, "stability": .8, "independence": 0},
                "conditions": [{"type": "EvidenceReady", "status": condition_status,
                                "reason": "AllDimensionsAvailable"}],
            },
        }

    def test_refresh_fabric_assessments_indexes_node_subjects(self):
        payload = {"items": [self.assessment(), {
            "metadata": {"name": "unsupported"},
            "spec": {"subjectRef": {"kind": "Service", "name": "app"},
                     "scope": {"plane": "pod"}},
        }]}
        with mock.patch.object(authority, "FABRIC_EVIDENCE_MODE", "Optional"), \
             mock.patch.object(authority, "kubernetes_get", return_value=payload):
            authority.refresh_fabric_assessments()
        self.assertTrue(authority.FABRIC_API_AVAILABLE)
        self.assertEqual(set(authority.FABRIC_ASSESSMENTS), {"edge-node"})

    def test_optional_fabric_evidence_allows_absent_provider(self):
        with mock.patch.object(authority, "FABRIC_EVIDENCE_MODE", "Optional"):
            result = authority.fabric_evidence({"nodeName": "edge-node"})
        self.assertTrue(result["eligible"])
        self.assertEqual(result["reason"], "ProviderUnavailable")

    def test_required_fabric_evidence_rejects_absent_assessment(self):
        with mock.patch.object(authority, "FABRIC_EVIDENCE_MODE", "Required"), \
             mock.patch.object(authority, "FABRIC_API_AVAILABLE", True):
            result = authority.fabric_evidence({"nodeName": "edge-node"})
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "AssessmentNotFound")

    def test_matching_stale_assessment_fails_closed(self):
        authority.FABRIC_ASSESSMENTS["edge-node"] = self.assessment(
            valid_until="2026-09-08T00:00:30Z"
        )
        with mock.patch.object(authority, "FABRIC_EVIDENCE_MODE", "Optional"):
            result = authority.fabric_evidence({"nodeName": "edge-node"}, now=1788825700)
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "EvidenceExpired")

    def test_fresh_assessment_contributes_only_confident_dimensions(self):
        authority.FABRIC_ASSESSMENTS["edge-node"] = self.assessment()
        with mock.patch.object(authority, "FABRIC_EVIDENCE_MODE", "Required"), \
             mock.patch.object(authority, "FABRIC_EVIDENCE_MIN_CONFIDENCE", .85), \
             mock.patch.object(authority, "FABRIC_EVIDENCE_WEIGHTS",
                               {"optimality": 100, "stability": 100, "independence": 100}):
            result = authority.fabric_evidence({"nodeName": "edge-node"}, now=1788825600)
        self.assertTrue(result["eligible"])
        self.assertEqual(result["score"], 80)

    def test_disabled_and_draining_edges_are_not_candidates(self):
        payload = {"items": [
            {"metadata": {"name": "disabled"}, "spec": {"enabled": False, "draining": False}},
            {"metadata": {"name": "draining"}, "spec": {"enabled": True, "draining": True}},
        ]}
        original = authority.kubernetes_get
        authority.kubernetes_get = lambda _path: payload
        try:
            self.assertEqual(authority.candidates_from_public_edges(), [])
        finally:
            authority.kubernetes_get = original

    def test_public_edge_builds_service_probe(self):
        payload = {"items": [{
            "metadata": {"name": "edge-a"},
            "spec": {
                "enabled": True, "draining": False, "region": "test", "gatewayVIP": "10.251.0.4",
                "endpoint": {"type": "PublicIP", "value": "192.0.2.10"},
                "serviceClasses": ["web"],
            },
        }]}
        original = authority.kubernetes_get
        authority.kubernetes_get = lambda _path: payload
        try:
            candidates = authority.candidates_from_public_edges()
        finally:
            authority.kubernetes_get = original
        self.assertEqual(candidates[0]["probes"]["app"], "https://app.example.com/healthz")

    def test_dns_fails_closed_without_ready_edge(self):
        query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + authority.encode_name("app.example.com.") + struct.pack("!HH", 1, 1)
        response = authority.dns_response(query)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)

    def test_explicit_statuses_reject_redirect_loop(self):
        authority.SERVICE_DEFINITIONS = {
            "login.example.com.": {
                "service": "dex",
                "class": "web",
                "probePath": "/.well-known/openid-configuration",
                "acceptedStatuses": [200],
            }
        }
        self.assertTrue(authority.accepted_probe_status("dex", 200))
        self.assertFalse(authority.accepted_probe_status("dex", 308))

    def test_area_prefers_high_capacity_local_edge(self):
        original_area = authority.AREA
        authority.AREA = "CN"
        authority.CANDIDATES[:] = [
            {"id": "small-edge", "region": "region-a", "area": "CN", "ip": "192.0.2.1", "capacityMbps": 100, "priority": 0, "probes": {"app": "https://app.example.com/"}},
            {"id": "large-edge", "region": "region-b", "area": "CN", "ip": "192.0.2.2", "capacityMbps": 1000, "priority": 0, "probes": {"app": "https://app.example.com/"}},
        ]
        authority.HEALTH["app"] = {name: {"ready": True, "latencyMs": 10} for name in ("small-edge", "large-edge")}
        try:
            self.assertEqual(authority.ranked("app")[0]["id"], "large-edge")
        finally:
            authority.AREA = original_area

    def test_us_prefers_regional_relay_over_remote_capacity(self):
        original_area = authority.AREA
        authority.AREA = "US"
        authority.CANDIDATES[:] = [
            {"id": "us-relay", "region": "los-angeles", "area": "US", "ip": "192.0.2.3", "capacityMbps": 100, "priority": 0, "forwarding": {"mode": "RegionalRelay", "originArea": "CN"}, "probes": {"app": "https://app.example.com/"}},
            {"id": "remote-origin", "region": "region-b", "area": "CN", "ip": "192.0.2.2", "capacityMbps": 1000, "priority": 0, "probes": {"app": "https://app.example.com/"}},
        ]
        authority.HEALTH["app"] = {name: {"ready": True, "latencyMs": 10} for name in ("us-relay", "remote-origin")}
        try:
            self.assertEqual(authority.ranked("app")[0]["id"], "us-relay")
        finally:
            authority.AREA = original_area

    def test_publisher_refreshes_per_service_edge_status(self):
        authority.CANDIDATES[:] = [{
            "id": "edge-a", "region": "test", "area": "test", "ip": "192.0.2.10",
            "probes": {"app": "https://app.example.com/healthz"},
        }]
        authority.HEALTH = {"app": {"edge-a": {
            "ready": False, "statusCode": 404, "latencyMs": 9,
            "observedAt": 123, "failure": "unexpected status",
        }}}
        with mock.patch.object(authority, "NODE", "publisher"), \
             mock.patch.object(authority, "PUBLISHER_NODE", "publisher"), \
             mock.patch.object(authority, "KUBERNETES_API", "kubernetes"), \
             mock.patch.object(authority, "kubernetes_patch") as patch:
            authority.publish_edge_statuses()
        path, payload = patch.call_args.args
        self.assertEqual(path, "/apis/networking.re8ch.com/v1alpha1/publicedges/edge-a/status")
        self.assertEqual(payload["status"]["conditions"][0]["status"], "False")
        self.assertEqual(payload["status"]["services"]["app"]["statusCode"], 404)

    def test_legacy_publication_is_disabled_by_default(self):
        with mock.patch.object(authority, "PUBLICATION_ENABLED", False), \
             mock.patch.object(authority, "NODE", "publisher"), \
             mock.patch.object(authority, "PUBLISHER_NODE", "publisher"), \
             mock.patch.object(authority, "PUBLICATION_REFS", {"app": {"namespace": "default", "name": "app"}}), \
             mock.patch.object(authority, "kubernetes_get") as get:
            authority.publish_default_area()
        get.assert_not_called()

    def test_named_publication_adapters_patch_each_provider_object(self):
        adapters = {
            "alidns": {
                "provider": "alibabacloud",
                "refs": {"app": {"namespace": "dns", "name": "app-alidns"}},
            },
            "dnspod": {
                "provider": "tencent-dnspod",
                "refs": {"app": {"namespace": "dns", "name": "app-dnspod"}},
            },
        }
        selected = {"id": "edge-a", "ip": "192.0.2.10", "state": "ready"}
        with mock.patch.object(authority, "PUBLICATION_ENABLED", True), \
             mock.patch.object(authority, "NODE", "publisher"), \
             mock.patch.object(authority, "PUBLISHER_NODE", "publisher"), \
             mock.patch.object(authority, "PUBLICATION_ADAPTERS", adapters), \
             mock.patch.object(authority, "ranked", return_value=[selected]), \
             mock.patch.object(authority, "kubernetes_get", return_value={"metadata": {"annotations": {}}}), \
             mock.patch.object(authority, "kubernetes_patch") as patch:
            authority.publish_default_area()
        self.assertEqual(patch.call_count, 2)
        paths = {call.args[0] for call in patch.call_args_list}
        self.assertEqual(paths, {
            "/apis/networking.k8s.io/v1/namespaces/dns/ingresses/app-alidns",
            "/apis/networking.k8s.io/v1/namespaces/dns/ingresses/app-dnspod",
        })
        annotations = [call.args[1]["metadata"]["annotations"] for call in patch.call_args_list]
        self.assertEqual({item[f"{authority.API_GROUP}/dns-provider"] for item in annotations}, {
            "alibabacloud", "tencent-dnspod",
        })

    def test_disabled_publication_adapter_is_skipped(self):
        adapters = {
            "esa": {
                "enabled": False,
                "provider": "alibaba-esa",
                "refs": {"app": {"namespace": "dns", "name": "app-esa"}},
            }
        }
        with mock.patch.object(authority, "PUBLICATION_ENABLED", True), \
             mock.patch.object(authority, "NODE", "publisher"), \
             mock.patch.object(authority, "PUBLISHER_NODE", "publisher"), \
             mock.patch.object(authority, "PUBLICATION_ADAPTERS", adapters), \
             mock.patch.object(authority, "kubernetes_get") as get:
            authority.publish_default_area()
        get.assert_not_called()

    def test_publication_adapters_reject_shared_objects(self):
        adapters = {
            name: {
                "provider": name,
                "refs": {"app": {"namespace": "dns", "name": "shared"}},
            }
            for name in ("alidns", "dnspod")
        }
        with mock.patch.object(authority, "PUBLICATION_ADAPTERS", adapters):
            with self.assertRaisesRegex(RuntimeError, "is shared by adapters"):
                authority.validate_publication_adapters()

    def test_custom_api_group_is_used_for_status(self):
        authority.CANDIDATES[:] = [{
            "id": "edge-a", "region": "test", "area": "test", "ip": "192.0.2.10",
            "probes": {"app": "https://app.example.com/healthz"},
        }]
        authority.HEALTH = {"app": {"edge-a": {"ready": True}}}
        with mock.patch.object(authority, "API_GROUP", "networking.example.org"), \
             mock.patch.object(authority, "NODE", "publisher"), \
             mock.patch.object(authority, "PUBLISHER_NODE", "publisher"), \
             mock.patch.object(authority, "KUBERNETES_API", "kubernetes"), \
             mock.patch.object(authority, "kubernetes_patch") as patch:
            authority.publish_edge_statuses()
        self.assertEqual(
            patch.call_args.args[0],
            "/apis/networking.example.org/v1alpha1/publicedges/edge-a/status",
        )

    def test_readiness_gate_matches_selected_ready_address(self):
        gate = {
            "app": {
                "configMap": {"namespace": "system", "name": "authority", "dataKey": "authority.json"},
                "requiredFields": {"source": "election"},
                "addressPath": ["leader", "address"],
                "endpointSlice": {"namespace": "backend", "name": "primary"},
            }
        }
        responses = [
            {"data": {"authority.json": '{"source":"election","leader":{"address":"10.0.0.8"}}'}},
            {"endpoints": [{"conditions": {"ready": True}, "addresses": ["10.0.0.8"]}]},
        ]
        with mock.patch.object(authority, "READINESS_GATES", gate), \
             mock.patch.object(authority, "kubernetes_get", side_effect=responses):
            self.assertTrue(authority.readiness_gate_ready("app"))

    def test_readiness_gate_fails_closed_on_conflicting_evidence(self):
        gate = {
            "app": {
                "configMap": {"namespace": "system", "name": "authority", "dataKey": "authority.json"},
                "addressPath": ["leader", "address"],
                "endpointSlice": {"namespace": "backend", "name": "primary"},
            }
        }
        responses = [
            {"data": {"authority.json": '{"leader":{"address":"10.0.0.8"}}'}},
            {"endpoints": [{"conditions": {"ready": True}, "addresses": ["10.0.0.9"]}]},
        ]
        with mock.patch.object(authority, "READINESS_GATES", gate), \
             mock.patch.object(authority, "kubernetes_get", side_effect=responses):
            self.assertFalse(authority.readiness_gate_ready("app"))


if __name__ == "__main__":
    unittest.main()
