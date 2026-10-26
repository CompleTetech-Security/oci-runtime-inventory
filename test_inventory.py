"""Synthetic local archive fixtures; no Docker, extraction or native execution."""
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import oci_runtime_inventory as c


def tar_bytes(entries, fmt=tarfile.USTAR_FORMAT):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=fmt) as archive:
        for entry in entries:
            name, data = entry[:2]
            kind = entry[2] if len(entry) > 2 else tarfile.REGTYPE
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind in {tarfile.REGTYPE, tarfile.AREGTYPE} else 0
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                info.linkname = entry[3] if len(entry) > 3 else "../outside"
            archive.addfile(info, io.BytesIO(data) if info.size else None)
    return out.getvalue()


def package(name="sharp", version="0.35.5"):
    return json.dumps({"name": name, "version": version, "scripts": {"postinstall": "NEVER-EXECUTE"}}).encode()


def docker_archive(layers, config=None):
    config = config or b'{"Hostname":"PRIVATE-HOST","Env":["TOKEN=PRIVATE-TOKEN"],"Cmd":["NEVER-EXECUTE"]}'
    manifest = [{"Config": "config.json", "RepoTags": ["PRIVATE-TAG:latest"], "Layers": [f"layer{i}.tar" for i in range(len(layers))]}]
    return tar_bytes([("manifest.json", json.dumps(manifest).encode()), ("config.json", config), *[(f"layer{i}.tar", data) for i, data in enumerate(layers)]])


def oci_archive(layers, compressed=False, bad_digest=False):
    blobs = []
    def blob(data, media):
        digest = hashlib.sha256(data).hexdigest()
        blobs.append(("blobs/sha256/" + digest, data))
        return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}
    config = blob(b'{"Env":["PRIVATE-TOKEN"]}', "application/vnd.oci.image.config.v1+json")
    descriptors = [blob(gzip.compress(data, mtime=0) if compressed else data, "application/vnd.oci.image.layer.v1.tar" + ("+gzip" if compressed else "")) for data in layers]
    manifest = {"schemaVersion": 2, "config": config, "layers": descriptors}
    descriptor = blob(json.dumps(manifest).encode(), "application/vnd.oci.image.manifest.v1+json")
    if bad_digest:
        # Keep descriptor/name and mutate content, so verification must reject it.
        name, raw = blobs[-1]
        blobs[-1] = (name, raw + b" ")
        descriptor["size"] += 1
    index = {"schemaVersion": 2, "manifests": [descriptor]}
    return tar_bytes([("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", json.dumps(index).encode()), *blobs])


class InventoryTests(unittest.TestCase):
    def cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = c.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def scan(self, archive, *args):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            path.write_bytes(archive)
            code, out, err = self.cli("--archive", str(path), *args)
            return code, json.loads(out), err

    def test_gzip_header_work_is_globally_bounded(self):
        layer=tar_bytes([('app/package.json',package())])
        archive=oci_archive([layer],compressed=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            members=[(m.name,stream.extractfile(m).read()) for m in stream if m.isfile()]
        # Rewrite gzip FNAME and the affected blob/manifest/index descriptors.
        compressed=gzip.compress(layer,mtime=0)
        malicious=compressed[:3]+bytes([8])+compressed[4:10]+b'x'*1000+b'\0'+compressed[10:]
        blobs=dict(members);index=json.loads(blobs['index.json']);old=index['manifests'][0]
        manifest=json.loads(blobs['blobs/sha256/'+old['digest'][7:]])
        digest=hashlib.sha256(malicious).hexdigest();blobs['blobs/sha256/'+digest]=malicious
        manifest['layers'][0].update(digest='sha256:'+digest,size=len(malicious))
        raw=json.dumps(manifest).encode();digest=hashlib.sha256(raw).hexdigest();blobs['blobs/sha256/'+digest]=raw
        old.update(digest='sha256:'+digest,size=len(raw));blobs['index.json']=json.dumps(index).encode()
        with mock.patch.object(c,'MAX_READ_CALLS',100):
            code,report,_=self.scan(tar_bytes(list(blobs.items())))
        self.assertEqual(2,code);self.assertIn('read_calls_limit',report['images'][0]['notes'])
        self.assertEqual([],report['images'][0]['components'])

    def test_unsupported_image_plan_preserves_valid_sibling(self):
        archive=oci_archive([tar_bytes([('app/package.json',package())])])
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            blobs={m.name:stream.extractfile(m).read() for m in stream if m.isfile()}
        index=json.loads(blobs['index.json']);descriptor=index['manifests'][0]
        bad=json.loads(blobs['blobs/sha256/'+descriptor['digest'][7:]])
        bad['layers'][0]['mediaType']='application/vnd.oci.image.layer.v1.tar+zstd'
        raw=json.dumps(bad).encode();digest=hashlib.sha256(raw).hexdigest();blobs['blobs/sha256/'+digest]=raw
        index['manifests'].append(dict(digest='sha256:'+digest,size=len(raw),mediaType='application/vnd.oci.image.manifest.v1+json'))
        blobs['index.json']=json.dumps(index).encode()
        for reverse in (False,True):
            if reverse:
                index['manifests'].reverse();blobs['index.json']=json.dumps(index).encode()
            code,report,_=self.scan(tar_bytes(list(blobs.items())))
            self.assertEqual(2,code);self.assertEqual(2,len(report['images']))
            valid=next(image for image in report['images'] if image['coverage_complete'])
            failed=next(image for image in report['images'] if not image['coverage_complete'])
            self.assertEqual('sharp',valid['components'][0]['name'])
            self.assertEqual([],failed['components']);self.assertIn('unsupported_layer_media_type',failed['notes'])

    def test_failed_publication_removes_sensitive_staging_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/"report.json"
            for force in (False,True):
                if force:output.write_text("existing",encoding="utf-8")
                state={"published":False,"publication_started":False}
                with mock.patch.object(c.os,"replace" if force else "link",side_effect=OSError("simulated failure")):
                    with self.assertRaises(OSError):c.publish({"private":"synthetic"},output,force,state)
                self.assertEqual([],list(root.glob(".oci-report-*")))
                if force:self.assertEqual("existing",output.read_text())

    def test_review_resource_padding_v7_index_hold_and_namespace(self):
        # No traversal of a lower filesystem for an empty layer.
        class NoTraversal(dict):
            def __iter__(self): raise AssertionError("empty layer must not traverse")
        c.apply_layer(NoTraversal({"app":("dir",None,"")}),{},set(),set())
        raw=bytearray(tar_bytes([("app/",b"",tarfile.DIRTYPE),("app/package.json",package())]))
        raw[156]=0;raw[148:156]=b"        "
        raw[148:156]=f"{sum(raw[:512]):06o}\0 ".encode()
        code,report,_=self.scan(docker_archive([bytes(raw)]))
        self.assertEqual(0,code);self.assertEqual("sharp",report["images"][0]["components"][0]["name"])
        for compressed in (False,True):
            code,report,_=self.scan(oci_archive([tar_bytes([])+b"\0"*(1024**2+1)],compressed=compressed))
            self.assertEqual(2,code)
        held=b"Package: nodejs\nVersion: 24.22.0\nStatus: hold ok installed\n"
        code,report,_=self.scan(docker_archive([tar_bytes([("var/lib/dpkg/status",held)])]))
        self.assertEqual("24.22.0",report["images"][0]["components"][0]["version"])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"sbom.json"
            path.write_text(json.dumps(dict(bomFormat="CycloneDX",specVersion="1.6",components=[dict(group="@vendor",name="sharp",version="0.35.5",components=[dict(name="flowise",version="3.1.3")])])),encoding="utf-8")
            report=dict(sboms=[]);c.scan_sbom(path,report,c.Budget())
            self.assertEqual(["flowise"],[r["name"] for r in report["sboms"][0]["components"]])
        # Replace the outer index version while retaining valid manifest descriptors.
        archive=oci_archive([tar_bytes([])])
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            members=[(m.name,stream.extractfile(m).read()) for m in stream if m.isfile()]
        members=[(name,data.replace(b'"schemaVersion": 2',b'"schemaVersion": 3') if name=="index.json" else data) for name,data in members]
        self.assertEqual(2,self.scan(tar_bytes(members))[0])

    def test_each_layer_rejects_inaccessible_metadata_and_serialized_unicode_limit(self):
        code, report, _ = self.scan(docker_archive([
            tar_bytes([("app", b"", tarfile.SYMTYPE), ("app/package.json", package())]),
            tar_bytes([("app", b"", tarfile.DIRTYPE)]),
        ]))
        self.assertEqual(2,code)
        self.assertEqual([],report["images"][0]["components"])
        row=dict(name="nodejs",version="α"*512)
        value=dict(images=[],sboms=[dict(coverage_complete=True,components=[row]*1400)])
        with self.assertRaises(c.InventoryError): c.export_inventory(value,"node2shell")

    def test_copilot_whiteout_deflate_provenance_and_consumer_bounds(self):
        code, report, _ = self.scan(docker_archive([tar_bytes([("app/package.json", package())]), tar_bytes([("app/.wh.", b"")])]))
        self.assertEqual(2, code)
        self.assertEqual([], report["images"][0]["components"])
        raw = docker_archive([tar_bytes([("app/package.json", package())])])
        with mock.patch.object(c, "layer_entries", side_effect=c.zlib.error("bad DEFLATE")):
            code, report, _ = self.scan(raw)
            self.assertEqual(2, code)
            self.assertEqual("image_invalid_or_unavailable", report["images"][0]["notes"][0])
        row = dict(name="sharp", version="0.35.5")
        report = dict(images=[], sboms=[dict(coverage_complete=True, components=[row] * 1001)])
        with self.assertRaises(c.InventoryError): c.export_inventory(report, "sharp")
        self.assertEqual(report, c.export_inventory(report, "canonical"))
        report["sboms"][0]["components"] = [dict(name="nodejs", version="24.22.0")] * 10001
        with self.assertRaises(c.InventoryError): c.export_inventory(report, "node2shell")
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"sbom.json"
            path.write_text(json.dumps(dict(bomFormat="CycloneDX", specVersion="1.6", metadata=dict(component=dict(name="sharp", version="0.35.5")))),encoding="utf-8")
            report=dict(images=[],sboms=[])
            c.scan_sbom(path,report,c.Budget(512*1024**2))
            self.assertEqual("metadata/component",report["sboms"][0]["components"][0]["path"])

    def test_docker_and_oci_plain_gzip_layers_have_digest_layer_file_provenance(self):
        layer = tar_bytes([("app/node_modules/sharp/package.json", package()), ("app/node_modules/flowise/package.json", package("flowise", "3.1.3"))])
        for archive in [docker_archive([layer]), oci_archive([layer]), oci_archive([layer], compressed=True)]:
            with self.subTest(size=len(archive)):
                code, report, err = self.scan(archive)
                self.assertEqual((0, ""), (code, err))
                self.assertTrue(report["complete"])
                image = report["images"][0]
                self.assertTrue(image["coverage_complete"])
                self.assertTrue(image["digest"].startswith("sha256:"))
                self.assertEqual({"sharp", "flowise"}, {r["name"] for r in image["components"]})
                for row in image["components"]:
                    self.assertTrue(row["layer_digest"].startswith("sha256:"))
                    self.assertEqual("not_tested", row["exploitability"])
                for private in ["PRIVATE-HOST", "PRIVATE-TOKEN", "PRIVATE-TAG", "NEVER-EXECUTE"]:
                    self.assertNotIn(private, json.dumps(report))

    def test_replaced_and_whiteout_deleted_metadata_does_not_survive(self):
        path = "app/node_modules/sharp/package.json"
        lower = tar_bytes([(path, package(version="0.35.4"))])
        upper = tar_bytes([(path, package(version="0.35.5"))])
        code, report, _ = self.scan(docker_archive([lower, upper]))
        self.assertEqual(0, code)
        self.assertEqual(["0.35.5"], [r["version"] for r in report["images"][0]["components"]])
        deletion = tar_bytes([("app/node_modules/sharp/.wh.package.json", b"")])
        _, report, _ = self.scan(docker_archive([lower, deletion]))
        self.assertEqual([], report["images"][0]["components"])

    def test_opaque_whiteouts_only_remove_lower_layer_entries_independent_of_order(self):
        lower = tar_bytes([("app/node_modules/sharp/package.json", package()), ("app/node_modules/flowise/package.json", package("flowise"))])
        for entries in [
            [("app/node_modules/.wh..wh..opq", b""), ("app/node_modules/flowise/package.json", package("flowise", "3.1.2"))],
            [("app/node_modules/flowise/package.json", package("flowise", "3.1.2")), ("app/node_modules/.wh..wh..opq", b"")],
        ]:
            _, report, _ = self.scan(docker_archive([lower, tar_bytes(entries)]))
            self.assertEqual([("flowise", "3.1.2")], [(r["name"], r["version"]) for r in report["images"][0]["components"]])

    def test_symlinks_hardlinks_devices_never_open_host_paths_or_retain_replaced_files(self):
        path = "app/package.json"
        lower = tar_bytes([(path, package())])
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE]:
            upper = tar_bytes([(path, b"", kind, "/private/host/package.json")])
            code, report, _ = self.scan(docker_archive([lower, upper]))
            self.assertEqual(0, code)
            self.assertEqual([], report["images"][0]["components"])

    def test_metadata_below_link_is_incomplete_not_followed(self):
        layer = tar_bytes([("app", b"", tarfile.SYMTYPE, "/host"), ("app/package.json", package())])
        code, report, _ = self.scan(docker_archive([layer]))
        self.assertEqual(2, code)
        self.assertFalse(report["complete"])
        self.assertEqual([], report["images"][0]["components"])

    def test_unsafe_duplicate_sparse_and_extended_members_fail_closed(self):
        for layer in [
            tar_bytes([("../package.json", package())]),
            tar_bytes([("/package.json", package())]),
            tar_bytes([("C:/package.json", package())]),
            tar_bytes([("app/package.json", package()), ("app/package.json", package(version="0.35.4"))]),
            tar_bytes([("app/package.json", b"", tarfile.GNUTYPE_SPARSE)]),
            tar_bytes([("app/" + "long" * 40 + "/package.json", package())], fmt=tarfile.PAX_FORMAT),
        ]:
            code, report, _ = self.scan(docker_archive([layer]))
            self.assertEqual(2, code)
            self.assertFalse(report["complete"])
        bad_outer = tar_bytes([("manifest.json", b"[]"), ("manifest.json", b"[]")])
        self.assertEqual(2, self.scan(bad_outer)[0])

    def test_truncated_checksum_and_blob_digest_mismatch_are_incomplete(self):
        valid = docker_archive([tar_bytes([("app/package.json", package())])])
        corrupt = bytearray(valid)
        corrupt[0] ^= 1
        for data in [valid[:200], bytes(corrupt), oci_archive([tar_bytes([])], bad_digest=True)]:
            code, report, _ = self.scan(data)
            self.assertEqual(2, code)
            self.assertFalse(report["complete"])

    def test_limits_bound_gzip_expansion_and_selected_file_capture(self):
        compressed = oci_archive([tar_bytes([("unselected.bin",b"\0"*(17*1024**2))])], compressed=True)
        code, report, _ = self.scan(compressed, "--max-expanded-mib", "16")
        self.assertEqual(2, code)
        self.assertIn("expanded_limit", report["images"][0]["notes"])
        layer = tar_bytes([("app/package.json", b" " * (c.MAX_JSON + 1))])
        code, report, _ = self.scan(docker_archive([layer]))
        self.assertEqual(2, code)
        self.assertIn("selected_file_byte_limit", report["images"][0]["notes"])

    def test_node_versions_only_come_from_package_database_not_tags_or_binary_names(self):
        status = b"Package: nodejs\nStatus: install ok installed\nVersion: 24.22.1-1vendor\n\n"
        layer = tar_bytes([("var/lib/dpkg/status", status), ("usr/bin/node-v99.1.0", b"not executed")])
        code, report, _ = self.scan(docker_archive([layer]))
        self.assertEqual(0, code)
        self.assertEqual(["24.22.1-1vendor"], [r["version"] for r in report["images"][0]["components"]])
        self.assertNotIn("99.1.0", json.dumps(report))
        inventory = c.export_inventory(report, "node2shell")
        self.assertEqual("offline_metadata_unverified", inventory[0]["build_source"])

    def test_consumer_exports_preserve_uncertainty_and_cover_empty_results(self):
        layer = tar_bytes([("app/node_modules/sharp/package.json", package()), ("app/node_modules/flowise/package.json", package("flowise", "3.1.3"))])
        _, report, _ = self.scan(docker_archive([layer]))
        sharp = c.export_inventory(report, "sharp")
        self.assertEqual("unknown", sharp["records"][0]["library_source"])
        flowise = c.export_inventory(report, "flowise")
        self.assertEqual("offline_metadata_unverified", flowise[0]["build_source"])
        empty = {"images": [], "sboms": [], "complete": False}
        self.assertEqual("", c.export_inventory(empty, "node2shell")[0]["node_version"])
        self.assertEqual(["flowise", "flowise-components"], [r["package"] for r in c.export_inventory(empty, "flowise")])

    def test_sbom_subject_components_spdx_and_malformed_types(self):
        fixtures = [
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": "sharp", "version": "0.35.5", "components": [{"name": "flowise", "version": "3.1.3"}]}}},
            {"spdxVersion": "SPDX-2.3", "packages": [{"name": "sharp", "versionInfo": "0.35.5"}, {"name": "flowise", "versionInfo": "3.1.3"}]},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"
            for data in fixtures:
                path.write_text(json.dumps(data), encoding="utf-8")
                code, out, _ = self.cli("--sbom", str(path))
                self.assertEqual(0, code)
                report = json.loads(out)
                self.assertEqual(2, len(report["sboms"][0]["components"]))
                self.assertNotIn("digest", report["sboms"][0])  # No fabricated image identity.
            for data in [{"spdxVersion": []}, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": []}]}]:
                path.write_text(json.dumps(data), encoding="utf-8")
                code, out, _ = self.cli("--sbom", str(path))
                self.assertEqual(2, code)
                self.assertFalse(json.loads(out)["complete"])

    def test_output_protection_no_clobber_and_standalone_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "image.tar"
            source.write_bytes(docker_archive([tar_bytes([("app/package.json", package())])]))
            before = source.read_bytes()
            self.assertEqual(2, self.cli("--archive", str(source), "--output", str(source), "--force")[0])
            alias = root / "alias.tar"
            os.link(source, alias)
            self.assertEqual(2, self.cli("--archive", str(source), "--output", str(alias), "--force")[0])
            self.assertEqual(before, source.read_bytes())
            output = root / "report.json"
            output.write_text("preserve", encoding="utf-8")
            self.assertEqual(2, self.cli("--archive", str(source), "--output", str(output))[0])
            self.assertEqual("preserve", output.read_text(encoding="utf-8"))
            checker = root / "checker.py"
            checker.write_bytes(Path(c.__file__).read_bytes())
            result = subprocess.run([sys.executable, str(checker), "--archive", str(source)], capture_output=True, text=True, check=True)
            self.assertTrue(json.loads(result.stdout)["complete"])

    def test_interruptions_do_not_append_second_report_or_retry_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            path.write_bytes(docker_archive([tar_bytes([])]))
            with mock.patch.object(c, "scan_archive", side_effect=KeyboardInterrupt):
                code, out, _ = self.cli("--archive", str(path))
            self.assertEqual(130, code)
            self.assertFalse(json.loads(out)["complete"])
            class Partial(io.StringIO):
                writes = 0
                def write(self, text):
                    self.writes += 1
                    super().write(text[:20])
                    raise KeyboardInterrupt
            output = Partial()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                code = c.main(["--archive", str(path)])
            self.assertEqual(130, code)
            self.assertEqual(1, output.writes)


if __name__ == "__main__":
    unittest.main()
