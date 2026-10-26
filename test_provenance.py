"""Deterministic synthetic provenance tests; no registry or runtime access."""
import contextlib
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import oci_runtime_inventory as c


class ProvenanceTests(unittest.TestCase):
    def run_cli(self, args, when):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = c.main(args, clock=lambda: when)
        return code, out.getvalue(), err.getvalue()

    def test_clock_changes_only_generation_time_not_content_or_artifact_identity(self):
        source = Path(__file__).parent / "examples/inventory.sbom.json"
        reports = []
        for when in (datetime(2026, 1, 2, tzinfo=timezone.utc), datetime(2026, 1, 3, tzinfo=timezone.utc)):
            code, text, err = self.run_cli(["--sbom", str(source)], when)
            self.assertEqual((0, ""), (code, err))
            reports.append(json.loads(text))
        first, second = reports
        self.assertEqual("2026-01-02T00:00:00Z", first["generated_at"])
        self.assertNotEqual(first["generated_at"], second["generated_at"])
        self.assertEqual(first["content_sha256"], second["content_sha256"])
        self.assertEqual(first["sboms"], second["sboms"])
        self.assertEqual("not_tested", first["exploitability"])
        self.assertEqual(hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest(), first["tool"]["executable_sha256"])
        self.assertEqual(first["content_sha256"], c.content_identity(first))

    def test_empty_invalid_and_interrupted_reports_retain_single_run_context(self):
        when = datetime(2026, 1, 2, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "empty.json"
            source.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', encoding="utf-8")
            for mode in ("empty", "invalid", "interrupted"):
                if mode == "invalid":
                    source.write_text("invalid", encoding="utf-8")
                calls = []
                def clock():
                    calls.append(1)
                    return when
                with mock.patch.object(c, "scan_sbom", side_effect=KeyboardInterrupt) if mode == "interrupted" else contextlib.nullcontext():
                    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
                        code = c.main(["--sbom", str(source)], clock=clock)
                report = json.loads(out.getvalue())
                self.assertEqual({"empty": 0, "invalid": 2, "interrupted": 130}[mode], code)
                self.assertEqual([1], calls)
                self.assertEqual("2026-01-02T00:00:00Z", report["generated_at"])
                self.assertEqual(report["content_sha256"], c.content_identity(report))
                self.assertEqual(mode == "empty", report["complete"])

    def test_consumer_receipt_links_exact_export_without_changing_contract(self):
        source = Path(__file__).parent / "examples/inventory.sbom.json"
        when = datetime(2026, 1, 2, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            for consumer in ("node2shell", "sharp", "flowise"):
                receipt = Path(directory) / (consumer + ".json")
                code, text, err = self.run_cli(["--sbom", str(source), "--consumer", consumer, "--receipt", str(receipt)], when)
                self.assertEqual((0, ""), (code, err))
                envelope = json.loads(receipt.read_text(encoding="utf-8"))
                report = envelope["inventory"]
                self.assertEqual(consumer, envelope["consumer"])
                self.assertEqual(hashlib.sha256(text.encode("utf-8")).hexdigest(), envelope["export_sha256"])
                self.assertEqual(c.export_inventory(report, consumer), json.loads(text))
                self.assertNotIn("generated_at", text)
                self.assertEqual("2026-01-02T00:00:00Z", report["generated_at"])
                self.assertNotIn(str(source), receipt.read_text(encoding="utf-8"))
            # Neither an existing receipt nor an output alias may be overwritten.
            receipt.write_text("preserve", encoding="utf-8")
            code, text, _ = self.run_cli(["--sbom", str(source), "--consumer", "sharp", "--receipt", str(receipt)], when)
            self.assertEqual((2, ""), (code, text))
            self.assertEqual("preserve", receipt.read_text(encoding="utf-8"))
            output = Path(directory) / "alias.json"
            code, text, _ = self.run_cli(["--sbom", str(source), "--consumer", "sharp", "--receipt", str(output), "--output", str(output)], when)
            self.assertEqual((2, ""), (code, text))
            self.assertFalse(output.exists())

    def test_copied_and_symlinked_standalone_report_executed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "inventory.py"
            shutil.copyfile(c.__file__, copied)
            copied.write_bytes(copied.read_bytes() + b"\n# synthetic copy\n")
            source = Path(__file__).parent / "examples/inventory.sbom.json"
            paths = [copied]
            link = Path(directory) / "link.py"
            try:
                link.symlink_to(copied)
                paths.append(link)
            except OSError:
                pass
            for path in paths:
                result = subprocess.run([sys.executable, str(path), "--sbom", str(source)], capture_output=True, text=True, encoding="utf-8", timeout=15)
                self.assertEqual(0, result.returncode, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(hashlib.sha256(copied.read_bytes()).hexdigest(), report["tool"]["executable_sha256"])

    def test_partial_receipt_has_linked_export_and_publication_is_not_retried(self):
        when = datetime(2026, 1, 2, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "invalid.json"
            source.write_text("invalid", encoding="utf-8")
            receipt = Path(directory) / "receipt.json"
            code, text, _ = self.run_cli(["--sbom", str(source), "--consumer", "sharp", "--receipt", str(receipt)], when)
            self.assertEqual(2, code)
            envelope = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertFalse(envelope["inventory"]["complete"])
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), envelope["export_sha256"])
            receipt.unlink()
            original_publish = c.publish
            calls = []
            def interrupt_output(data, output, force, state):
                calls.append(output)
                if len(calls) == 2:
                    raise KeyboardInterrupt
                return original_publish(data, output, force, state)
            with mock.patch.object(c, "publish", side_effect=interrupt_output):
                code, text, _ = self.run_cli(["--sbom", str(source), "--consumer", "sharp", "--receipt", str(receipt)], when)
            self.assertEqual((130, ""), (code, text))
            self.assertEqual([receipt, None], calls)
            self.assertTrue(receipt.is_file())

    def test_clock_requires_an_aware_datetime(self):
        source = Path(__file__).parent / "examples/inventory.sbom.json"
        for invalid in (datetime(2026, 1, 2), "2026-01-02", None):
            code, text, _ = self.run_cli(["--sbom", str(source)], invalid)
            self.assertEqual((2, ""), (code, text))

    def test_receipt_staging_interrupt_preserves_exit_and_removes_private_temporary(self):
        source = Path(__file__).parent / "examples/inventory.sbom.json"
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            output = Path(directory) / "consumer.json"
            output.write_text("existing evidence", encoding="utf-8")
            with mock.patch.object(c.os, "fsync", side_effect=KeyboardInterrupt):
                code, text, _ = self.run_cli(["--sbom", str(source), "--consumer", "sharp", "--receipt", str(receipt),
                                              "--output", str(output), "--force"], datetime(2026, 1, 2, tzinfo=timezone.utc))
            self.assertEqual((130, ""), (code, text))
            self.assertFalse(receipt.exists())
            self.assertEqual("existing evidence", output.read_text(encoding="utf-8"))
            self.assertEqual([], list(Path(directory).glob(".oci-report-*")))

    def test_stdout_receipt_hash_matches_raw_utf8_bytes_despite_text_translation(self):
        source = Path(__file__).parent / "examples/inventory.sbom.json"
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "translated-receipt.json"
            raw = io.BytesIO()
            translated = io.TextIOWrapper(raw, encoding="utf-16", newline="\r\n")
            with contextlib.redirect_stdout(translated), contextlib.redirect_stderr(io.StringIO()):
                code = c.main(["--sbom", str(source), "--consumer", "sharp", "--receipt", str(receipt)])
            translated.flush()
            output_bytes = raw.getvalue()
            self.assertEqual(0, code)
            self.assertEqual(hashlib.sha256(output_bytes).hexdigest(), json.loads(receipt.read_text(encoding="utf-8"))["export_sha256"])
            self.assertNotIn(b"\r", output_bytes)
            self.assertIsInstance(json.loads(output_bytes.decode("utf-8")), dict)
            # Real redirected process stdout is captured as bytes on every CI OS.
            receipt = Path(directory) / "process-receipt.json"
            result = subprocess.run([sys.executable, c.__file__, "--sbom", str(source), "--consumer", "sharp", "--receipt", str(receipt)],
                                    capture_output=True, timeout=15)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), json.loads(receipt.read_text(encoding="utf-8"))["export_sha256"])

    def test_consumer_staging_interrupt_cleans_owned_temporary_but_retains_receipt(self):
        source = Path(__file__).parent / "examples/inventory.sbom.json"
        for force in (False, True):
            with self.subTest(force=force), tempfile.TemporaryDirectory() as directory:
                receipt = Path(directory) / "receipt.json"
                output = Path(directory) / "consumer.json"
                args = ["--sbom", str(source), "--consumer", "sharp", "--receipt", str(receipt), "--output", str(output)]
                if force:
                    output.write_bytes(b"previous consumer evidence")
                    args.append("--force")
                with mock.patch.object(c.os, "fsync", side_effect=[None, KeyboardInterrupt]) as sync:
                    code, text, _ = self.run_cli(args, datetime(2026, 1, 2, tzinfo=timezone.utc))
                self.assertEqual((130, ""), (code, text))
                self.assertEqual(2, sync.call_count)  # No second attempt to publish the pair.
                self.assertTrue(receipt.is_file())  # The committed receipt remains useful evidence.
                envelope = json.loads(receipt.read_text(encoding="utf-8"))
                expected = c.serialized(c.export_inventory(envelope["inventory"], "sharp")).encode("utf-8")
                self.assertEqual(hashlib.sha256(expected).hexdigest(), envelope["export_sha256"])
                self.assertEqual([], list(Path(directory).glob(".oci-report-*")))
                if force:
                    self.assertEqual(b"previous consumer evidence", output.read_bytes())
                else:
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
