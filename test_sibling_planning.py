"""Synthetic independent planning failures must not erase healthy siblings."""
import hashlib
import io
import json
import tarfile
import unittest
from unittest import mock

import oci_runtime_inventory as c
import test_inventory as t


def unpack(raw):
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        return {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}


def blob(files, value):
    raw = json.dumps(value).encode()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    files["blobs/sha256/" + digest[7:]] = raw
    return dict(digest=digest, size=len(raw), mediaType="application/vnd.oci.image.index.v1+json")


class SiblingPlanningTests(unittest.TestCase):
    cli = t.InventoryTests.cli
    scan = t.InventoryTests.scan

    def assert_siblings(self, files, identity, reason, kind):
        code, report, _ = self.scan(t.tar_bytes(list(files.items())))
        self.assertEqual(2, code)
        self.assertFalse(report["complete"])
        self.assertEqual(2, len(report["images"]))
        healthy = next(image for image in report["images"] if image["coverage_complete"])
        failed = next(image for image in report["images"] if not image["coverage_complete"])
        self.assertEqual(identity, healthy["digest"])
        self.assertEqual(kind, healthy["identity_kind"])
        self.assertEqual("sharp", healthy["components"][0]["name"])
        self.assertEqual("0.35.5", healthy["components"][0]["version"])
        self.assertEqual(healthy["layers"][0], healthy["components"][0]["layer_digest"])
        self.assertEqual("not_tested", healthy["components"][0]["exploitability"])
        self.assertEqual([], failed["components"])
        self.assertEqual([], failed["layers"])
        self.assertIn(reason, failed["notes"])
        code, consumer, _ = self.scan(t.tar_bytes(list(files.items())), "--consumer", "sharp")
        self.assertEqual(2, code)
        self.assertEqual([["0.35.5"]], [row["sharp_versions"] for row in consumer["records"]])
        return failed

    def test_nested_index_structural_failures_preserve_siblings_in_both_orders(self):
        original = unpack(t.oci_archive([t.tar_bytes([("app/package.json", t.package())])]))
        for malformed, reason in ((dict(schemaVersion=3, manifests=[]), "unsupported_index_schema_version"),
                                  (dict(schemaVersion=True, manifests=[]), "unsupported_index_schema_version"),
                                  (dict(schemaVersion=2, manifests="PRIVATE-CONTENT"), "invalid_or_excessive_image_index"),
                                  (dict(schemaVersion=2, manifests=[{}] * 17), "invalid_or_excessive_image_index")):
            for reverse in (False, True):
                with self.subTest(malformed=malformed, reverse=reverse):
                    files = dict(original)
                    index = json.loads(files["index.json"])
                    valid = index["manifests"][0]
                    rejected = blob(files, malformed)
                    index["manifests"] = [rejected, valid] if reverse else [valid, rejected]
                    files["index.json"] = json.dumps(index).encode()
                    failed = self.assert_siblings(files, valid["digest"], reason, "oci_manifest")
                    self.assertEqual(rejected["digest"], failed["digest"])
                    self.assertNotIn("PRIVATE-CONTENT", json.dumps(failed))

    def test_docker_planning_failures_preserve_siblings_in_both_orders(self):
        original = unpack(t.docker_archive([t.tar_bytes([("app/package.json", t.package())])]))
        identity = "sha256:" + hashlib.sha256(original["config.json"]).hexdigest()
        for malformed, reason, known_identity in ((dict(Config="config.json", Layers=["missing.tar"]), "missing_docker_layer", True),
                                                 (dict(Config="missing.json", Layers=[]), "missing_or_excessive_manifest", False),
                                                 (dict(Config="config.json", Layers="PRIVATE-CONTENT"), "invalid_docker_image_manifest", False),
                                                 (None, "invalid_docker_image_manifest", False),
                                                 (dict(Config="config.json", Layers=["../outside"]), "unsafe_archive_path", True)):
            for reverse in (False, True):
                with self.subTest(malformed=malformed, reverse=reverse):
                    files = dict(original)
                    valid = json.loads(files["manifest.json"])[0]
                    files["manifest.json"] = json.dumps([malformed, valid] if reverse else [valid, malformed]).encode()
                    failed = self.assert_siblings(files, identity, reason, "docker_config")
                    self.assertEqual(identity if known_identity else "unknown", failed["digest"])
                    self.assertNotIn("PRIVATE-CONTENT", json.dumps(failed))

    def test_valid_nested_index_is_still_traversed(self):
        files = unpack(t.oci_archive([t.tar_bytes([("app/package.json", t.package())])]))
        index = json.loads(files["index.json"])
        valid = index["manifests"][0]
        index["manifests"] = [blob(files, dict(schemaVersion=2, manifests=[valid]))]
        files["index.json"] = json.dumps(index).encode()
        code, report, _ = self.scan(t.tar_bytes(list(files.items())))
        self.assertEqual(0, code)
        self.assertEqual(valid["digest"], report["images"][0]["digest"])

    def test_nested_depth_limit_remains_local_and_bounded(self):
        files = unpack(t.oci_archive([t.tar_bytes([("app/package.json", t.package())])]))
        root = json.loads(files["index.json"])
        valid = root["manifests"][0]
        nested = valid
        for _ in range(4):
            nested = blob(files, dict(schemaVersion=2, manifests=[nested]))
        root["manifests"] = [valid, nested]
        files["index.json"] = json.dumps(root).encode()
        self.assert_siblings(files, valid["digest"], "invalid_or_excessive_image_index", "oci_manifest")

    def test_global_root_corruption_and_shared_capture_budget_remain_conservative(self):
        files = unpack(t.oci_archive([t.tar_bytes([("app/package.json", t.package())])]))
        files["index.json"] = json.dumps(dict(schemaVersion=3, manifests=[])).encode()
        code, report, _ = self.scan(t.tar_bytes(list(files.items())))
        self.assertEqual(2, code)
        self.assertEqual([], report["images"])
        files = unpack(t.docker_archive([t.tar_bytes([("app/package.json", t.package())])]))
        entry = json.loads(files["manifest.json"])[0]
        files["manifest.json"] = json.dumps([entry, entry]).encode()
        # Planning both configs exceeds this one shared budget; the failure
        # must not reset it and fabricate a complete second image.
        cap = len(files["manifest.json"]) + len(files["config.json"])
        with mock.patch.object(c, "MAX_CAPTURE", cap):
            code, report, _ = self.scan(t.tar_bytes(list(files.items())))
        self.assertEqual(2, code)
        self.assertTrue(all(not image["coverage_complete"] for image in report["images"]))
        self.assertEqual(cap, report["usage"]["capture"])
        self.assertTrue(all("capture_limit" in image["notes"] for image in report["images"]))


if __name__ == "__main__":
    unittest.main()
