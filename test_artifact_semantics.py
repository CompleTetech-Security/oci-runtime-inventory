"""Offline fixtures distinguish verified artifact bytes from image filesystems."""
import hashlib
import io
import json
import tarfile
import unittest

import test_inventory as t


class ArtifactSemanticsTests(unittest.TestCase):
    cli = t.InventoryTests.cli
    scan = t.InventoryTests.scan
    def test_unsupported_artifacts_never_supply_image_components(self):
        base = t.oci_archive([t.tar_bytes([("app/package.json", t.package())])])
        with tarfile.open(fileobj=io.BytesIO(base)) as archive:
            original = {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}
        for case in ("empty_config_artifact", "artifact_with_image_config", "unknown_descriptor",
                     "unknown_config", "missing_config_type", "unknown_manifest_type",
                     "non_string_descriptor", "non_string_config"):
            with self.subTest(case=case):
                files = dict(original)
                index = json.loads(files["index.json"])
                valid = index["manifests"][0]
                manifest = json.loads(files["blobs/sha256/" + valid["digest"][7:]])
                if case in ("empty_config_artifact", "artifact_with_image_config"):
                    manifest["artifactType"] = "application/vnd.example.attestation"
                if case == "empty_config_artifact":
                    raw = b"{}"
                    digest = hashlib.sha256(raw).hexdigest()
                    files["blobs/sha256/" + digest] = raw
                    manifest["config"] = dict(digest="sha256:" + digest, size=len(raw),
                                              mediaType="application/vnd.oci.empty.v1+json")
                if case == "unknown_config":
                    manifest["config"]["mediaType"] = "application/vnd.example.config+json"
                if case == "missing_config_type":
                    manifest["config"].pop("mediaType")
                if case == "non_string_config":
                    manifest["config"]["mediaType"] = []
                if case == "unknown_manifest_type":
                    manifest["mediaType"] = "application/vnd.example.manifest+json"
                raw = json.dumps(manifest).encode()
                digest = hashlib.sha256(raw).hexdigest()
                files["blobs/sha256/" + digest] = raw
                bad = dict(digest="sha256:" + digest, size=len(raw),
                           mediaType="application/vnd.oci.image.manifest.v1+json")
                if case == "unknown_descriptor":
                    bad["mediaType"] = "application/vnd.example.manifest+json"
                if case == "non_string_descriptor":
                    bad["mediaType"] = []
                # Descriptor identity remains distinct even when only its media type changes.
                for siblings in ([bad], [valid, bad], [bad, valid]):
                    index["manifests"] = siblings
                    files["index.json"] = json.dumps(index).encode()
                    payload = t.tar_bytes(list(files.items()))
                    code, report, _ = self.scan(payload)
                    self.assertEqual(2, code)
                    self.assertFalse(report["complete"])
                    failed = [image for image in report["images"] if not image["coverage_complete"]]
                    self.assertEqual(1, len(failed))
                    self.assertEqual(bad["digest"], failed[0]["digest"])
                    self.assertEqual([], failed[0]["components"])
                    self.assertTrue(any("unsupported" in note for note in failed[0]["notes"]))
                    healthy = [image for image in report["images"] if image["coverage_complete"]]
                    self.assertEqual(len(siblings) - 1, len(healthy))
                    if healthy:
                        self.assertEqual("sharp", healthy[0]["components"][0]["name"])
                    _, consumer, _ = self.scan(payload, "--consumer", "sharp")
                    # The failed artifact cannot create any additional consumer record.
                    if healthy:
                        self.assertEqual([["0.35.5"]], [row["sharp_versions"] for row in consumer["records"]])
                        self.assertEqual("not_tested", healthy[0]["components"][0]["exploitability"])
                    else:
                        self.assertEqual([{"asset_id": "metadata-coverage"}], consumer["records"])


if __name__ == "__main__":
    unittest.main()
