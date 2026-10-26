#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Offline bounded OCI/Docker-save inventory. Never extract or execute images."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import zlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

VERSION = "0.1.0"
SCHEMA_VERSION = "1.0"
MAX_ARCHIVE = 8 * 1024**3
MAX_JSON = 4 * 1024**2
MAX_MEMBERS = 100000
MAX_IMAGES = 16
MAX_LAYERS = 256
MAX_CAPTURE = 16 * 1024**2
TARGETS = {"sharp", "flowise", "flowise-components"}


class InventoryError(ValueError):
    """Messages identify failure classes without exposing input contents."""


def json_value(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InventoryError("duplicate_json_key")
            result[key] = value
        return result
    def reject(_):
        raise InventoryError("nonfinite_json")
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique, parse_constant=reject)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise InventoryError("invalid_json") from None
    pending, count = [(data, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 40 or count > 200000:
            raise InventoryError("json_structure_limit")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
    return data


def safe_path(value):
    if not isinstance(value, str) or len(value) > 512 or "\\" in value or ":" in value or value.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InventoryError("unsafe_archive_path")
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    if not value or value.count("/") > 63 or any(part in {"", ".", ".."} for part in value.split("/")):
        raise InventoryError("unsafe_archive_path")
    return value


def octal(field):
    value = field.strip(b" \0")
    if not re.fullmatch(b"[0-7]*", value):
        raise InventoryError("unsupported_tar_number")
    return int(value or b"0", 8)


def header(block):
    if len(block) != 512:
        raise InventoryError("truncated_tar_header")
    if octal(block[148:156]) != sum(block[:148]) + 8 * 32 + sum(block[156:]):
        raise InventoryError("invalid_tar_checksum")
    try:
        name = block[:100].split(b"\0", 1)[0].decode("utf-8")
        prefix = block[345:500].split(b"\0", 1)[0].decode("utf-8") if block[257:263] == b"ustar\0" else ""
    except UnicodeError:
        raise InventoryError("invalid_tar_name_encoding") from None
    kind = block[156:157]
    if kind not in {b"\0", b"0", b"1", b"2", b"3", b"4", b"5", b"6"}:
        raise InventoryError("unsupported_tar_extension_or_sparse_member")
    size = octal(block[124:136])
    if kind == b"\0" and name.endswith("/"):
        kind = b"5"  # Legacy V7 directory encoding.
    if kind not in {b"\0", b"0"} and size:
        raise InventoryError("special_member_has_data")
    path = "" if kind == b"5" and name in {".", "./"} and not prefix else safe_path(prefix + "/" + name if prefix else name)
    return path, size, "file" if kind in {b"\0", b"0"} else "dir" if kind == b"5" else "opaque"


def regular_input(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    stream = os.fdopen(fd, "rb")
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE:
        stream.close()
        raise InventoryError("input_not_bounded_regular_file")
    return stream, info.st_size


def archive_index(stream, length):
    """Index an uncompressed USTAR outer archive without extracting any member."""
    result, position, count = {}, 0, 0
    while position + 512 <= length:
        stream.seek(position)
        block = stream.read(512)
        position += 512
        if block == b"\0" * 512:
            if stream.read(512) != b"\0" * 512:
                raise InventoryError("invalid_tar_terminator")
            if length - stream.tell() > 1024**2:
                raise InventoryError("excessive_tar_trailing_padding")
            while True:
                trailing = stream.read(65536)
                if not trailing:
                    return result
                if trailing.strip(b"\0"):
                    raise InventoryError("nonzero_tar_trailing_data")
        path, size, kind = header(block)
        count += 1
        if count > MAX_MEMBERS:
            raise InventoryError("outer_member_limit")
        if not path and kind == "dir":
            continue
        if path in result or len(result) >= MAX_MEMBERS:
            raise InventoryError("duplicate_or_excessive_archive_members")
        if kind == "opaque":
            raise InventoryError("outer_archive_link_or_device")
        padded = (size + 511) // 512 * 512
        if position + padded > length:
            raise InventoryError("truncated_archive_member")
        result[path] = (position, size, kind)
        position += padded
    raise InventoryError("missing_tar_terminator")


MAX_READ_CALLS = 200000


class Budget:
    def __init__(self, expanded=512 * 1024**2):
        self.expanded_limit = expanded
        self.expanded = self.raw = self.members = self.capture = self.work = self.read_calls = 0

    def add(self, key, amount, maximum):
        value = getattr(self, key) + amount
        if value > maximum:
            raise InventoryError(key + "_limit")
        setattr(self, key, value)


class Segment:
    def __init__(self, stream, offset, size, budget):
        self.stream, self.position, self.remaining = stream, offset, size
        self.budget, self.digest = budget, hashlib.sha256()

    def read(self, size=-1):
        self.budget.add("read_calls", 1, MAX_READ_CALLS)
        size = min(self.remaining, 65536 if size < 0 else size)
        self.stream.seek(self.position)
        raw = self.stream.read(size)
        if len(raw) != size:
            raise InventoryError("truncated_blob")
        self.budget.add("raw", len(raw), 1024**3)
        self.digest.update(raw)
        self.position += len(raw)
        self.remaining -= len(raw)
        return raw


class Expanded:
    def __init__(self, stream, budget):
        self.stream, self.budget = stream, budget

    def read(self, size):
        raw = self.stream.read(size)
        self.budget.add("expanded", len(raw), self.budget.expanded_limit)
        return raw

    def exact(self, size):
        raw = self.read(size)
        if len(raw) != size:
            raise InventoryError("truncated_layer")
        return raw

    def discard(self, size):
        while size:
            amount = min(size, 65536)
            self.exact(amount)
            size -= amount


def selected_file(path):
    return path.endswith("/package.json") or path == "package.json" or path in {"var/lib/dpkg/status", "lib/apk/db/installed"}


def layer_entries(stream, budget, layer_digest):
    reader = Expanded(stream, budget)
    entries, removals, opaque_dirs = {}, set(), set()
    while True:
        block = reader.exact(512)
        if block == b"\0" * 512:
            if reader.exact(512) != b"\0" * 512:
                raise InventoryError("invalid_layer_terminator")
            padding = 0
            while True:
                raw = reader.read(65536)
                padding += len(raw)
                if padding > 1024**2:
                    raise InventoryError("excessive_layer_trailing_padding")
                if not raw:
                    return entries, removals, opaque_dirs
                if raw.strip(b"\0"):
                    raise InventoryError("nonzero_layer_trailing_data")
        path, size, kind = header(block)
        budget.add("members", 1, MAX_MEMBERS)
        if not path and kind == "dir":
            continue
        if path in entries:
            raise InventoryError("duplicate_layer_member")
        directory, _, basename = path.rpartition("/")
        if basename.startswith(".wh."):
            if kind != "file" or size:
                raise InventoryError("invalid_whiteout")
            if basename == ".wh..wh..opq":
                opaque_dirs.add(directory)
            else:
                if not basename[4:]:
                    raise InventoryError("invalid_whiteout")
                removals.add(safe_path((directory + "/" if directory else "") + basename[4:]))
            # Track normalized whiteout names too, rejecting duplicate markers.
            entries[path] = ("whiteout", None, layer_digest)
        else:
            content = None
            if kind == "file" and selected_file(path):
                if size > MAX_JSON:
                    raise InventoryError("selected_file_byte_limit")
                budget.add("capture", size, MAX_CAPTURE)
                content = reader.exact(size)
            else:
                reader.discard(size)
            entries[path] = (kind, content, layer_digest)
        reader.discard((-size) % 512)


def apply_layer(filesystem, entries, removals, opaque_dirs, budget=None):
    # Whiteouts affect lower layers regardless of ordering within this layer.
    replacing = {path for path, entry in entries.items() if entry[0] not in {"dir", "whiteout"}}
    if "" in opaque_dirs:
        filesystem.clear()
    elif removals or opaque_dirs or replacing:
        if budget is not None:
            budget.add("work",len(filesystem),2000000)
        for path in list(filesystem):
            parts = path.split("/")
            parents = ["/".join(parts[:i]) for i in range(1, len(parts))]
            if path in removals or any(parent in removals or parent in opaque_dirs or parent in replacing for parent in parents):
                del filesystem[path]
    filesystem.update({path: entry for path, entry in entries.items() if entry[0] != "whiteout"})
    if len(filesystem) > MAX_MEMBERS:
        raise InventoryError("filesystem_member_limit")


def descriptor_path(descriptor, index):
    if not isinstance(descriptor, dict) or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(descriptor.get("digest", ""))):
        raise InventoryError("unsupported_blob_digest")
    size = descriptor.get("size")
    name = "blobs/sha256/" + descriptor["digest"][7:]
    if type(size) is not int or size < 0 or name not in index or index[name][1] != size or index[name][2] != "file":
        raise InventoryError("missing_or_mismatched_blob")
    return name


def read_member(stream, index, name, budget=None):
    if name not in index or index[name][2] != "file" or index[name][1] > MAX_JSON:
        raise InventoryError("missing_or_excessive_manifest")
    offset, size, _ = index[name]
    if budget is not None:
        budget.add("capture", size, MAX_CAPTURE)
    stream.seek(offset)
    raw = stream.read(size)
    if len(raw) != size:
        raise InventoryError("truncated_manifest")
    return raw


def blob_json(stream, index, descriptor, budget):
    name = descriptor_path(descriptor, index)
    raw = read_member(stream, index, name, budget)
    if hashlib.sha256(raw).hexdigest() != descriptor["digest"][7:]:
        raise InventoryError("manifest_digest_mismatch")
    return json_value(raw)


def image_plans(stream, index, budget):
    def index_descriptors(document, depth):
        if not isinstance(document, dict) or type(document.get("schemaVersion")) is not int or document["schemaVersion"] != 2:
            raise InventoryError("unsupported_index_schema_version")
        descriptors = document.get("manifests")
        if depth > 3 or not isinstance(descriptors, list) or len(descriptors) > MAX_IMAGES:
            raise InventoryError("invalid_or_excessive_image_index")
        return descriptors

    plans = []
    if "oci-layout" in index:
        if json_value(read_member(stream, index, "oci-layout", budget)) != {"imageLayoutVersion": "1.0.0"}:
            raise InventoryError("unsupported_oci_layout")
        root = json_value(read_member(stream, index, "index.json", budget))
        pending = [(root, 0)]
        visits = 0
        while pending:
            document, depth = pending.pop()
            descriptors = index_descriptors(document, depth)
            for descriptor in descriptors:
                visits += 1
                if visits > 64:
                    raise InventoryError("image_descriptor_limit")
                try:
                    manifest = blob_json(stream, index, descriptor, budget)
                    media = descriptor.get("mediaType")
                    index_media = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
                    image_media = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
                    if not isinstance(media, str) or media not in index_media | image_media:
                        raise InventoryError("unsupported_manifest_media_type")
                    if not isinstance(manifest, dict) or ("mediaType" in manifest and manifest["mediaType"] != media):
                        raise InventoryError("unsupported_manifest_media_type")
                    if "artifactType" in manifest:
                        raise InventoryError("unsupported_oci_artifact")
                    if media in index_media:
                        # Reject malformed children inside this descriptor's
                        # failure boundary, before deferring their traversal.
                        index_descriptors(manifest, depth + 1)
                        pending.append((manifest, depth + 1))
                        continue
                    if not isinstance(manifest, dict) or type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 2 or not isinstance(manifest.get("layers"), list):
                        raise InventoryError("invalid_image_manifest")
                    if len(manifest["layers"]) > MAX_LAYERS:
                        raise InventoryError("image_layer_limit")
                    # Config is verified as opaque bytes, not parsed for Env/Cmd/host data.
                    config = manifest.get("config")
                    config_name = descriptor_path(config, index)
                    if hashlib.sha256(read_member(stream, index, config_name, budget)).hexdigest() != config["digest"][7:]:
                        raise InventoryError("config_digest_mismatch")
                    config_media = config.get("mediaType")
                    if not isinstance(config_media, str) or config_media not in {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}:
                        raise InventoryError("unsupported_image_config_media_type")
                    layers = []
                    for layer in manifest["layers"]:
                        name = descriptor_path(layer, index)
                        media = layer.get("mediaType", "")
                        if not isinstance(media, str) or media not in {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip"}:
                            raise InventoryError("unsupported_layer_media_type")
                        layers.append((name, media.endswith("gzip"), layer["digest"]))
                    plans.append((descriptor["digest"], layers, "oci_manifest", None))
                except InventoryError as exc:
                    identity=descriptor.get("digest", "unknown") if isinstance(descriptor,dict) else "unknown"
                    if not isinstance(identity,str) or re.fullmatch(r"sha256:[a-f0-9]{64}",identity) is None:
                        identity="unknown"
                    plans.append((identity, [], "oci_manifest", str(exc)))
                if len(plans) > MAX_IMAGES:
                    raise InventoryError("image_count_limit")
    elif "manifest.json" in index:
        manifests = json_value(read_member(stream, index, "manifest.json", budget))
        if not isinstance(manifests, list) or not manifests or len(manifests) > MAX_IMAGES:
            raise InventoryError("invalid_docker_manifest_list")
        for manifest in manifests:
            digest = "unknown"
            try:
                if not isinstance(manifest, dict) or not isinstance(manifest.get("Layers"), list) or len(manifest["Layers"]) > MAX_LAYERS:
                    raise InventoryError("invalid_docker_image_manifest")
                config = safe_path(manifest.get("Config"))
                digest = "sha256:" + hashlib.sha256(read_member(stream, index, config, budget)).hexdigest()
                layers = []
                for layer in manifest["Layers"]:
                    name = safe_path(layer)
                    if name not in index or index[name][2] != "file":
                        raise InventoryError("missing_docker_layer")
                    layers.append((name, False, None))
                plans.append((digest, layers, "docker_config", None))
            except InventoryError as exc:
                plans.append((digest, [], "docker_config", str(exc)))
    else:
        raise InventoryError("unsupported_archive_layout")
    if not plans:
        raise InventoryError("empty_image_index")
    return plans


def validate_selected_ancestors(filesystem, candidates=None):
    selected = filesystem if candidates is None else candidates
    for path, (kind, content, _) in selected.items():
        if kind != "file" or content is None:
            continue
        parts = path.split("/")
        if any(filesystem.get("/".join(parts[:i]), ("dir",))[0] != "dir" for i in range(1, len(parts))):
            raise InventoryError("metadata_under_nondirectory_ancestor")


def component_rows(filesystem):
    rows = []
    for path, (kind, content, layer) in sorted(filesystem.items()):
        if selected_file(path) and kind != "file":
            raise InventoryError("selected_metadata_not_regular_file")
        if kind != "file" or content is None:
            continue
        parts = path.split("/")
        if any(filesystem.get("/".join(parts[:i]), ("dir",))[0] != "dir" for i in range(1, len(parts))):
            raise InventoryError("metadata_under_nondirectory_ancestor")
        found = []
        if path.endswith("package.json"):
            data = json_value(content)
            if not isinstance(data, dict):
                raise InventoryError("invalid_package_manifest")
            if isinstance(data.get("name"), str) and data["name"] in TARGETS:
                found.append((data["name"], "npm", data.get("version", "")))
        elif path == "var/lib/dpkg/status":
            try:
                text = content.decode("utf-8")
            except UnicodeError:
                raise InventoryError("invalid_package_database_encoding") from None
            for stanza in re.split(r"\r?\n\r?\n", text):
                pairs = re.findall(r"^(Package|Version|Status):[ \t]*(.*)$", stanza, re.M)
                if len({key for key, _ in pairs}) != len(pairs):
                    raise InventoryError("duplicate_package_database_field")
                fields = {key: value.rstrip("\r") for key, value in pairs}
                if fields.get("Package") == "nodejs" and re.fullmatch(r"(?:install|hold|deinstall|purge|unknown) ok installed",fields.get("Status", "")) is not None:
                    found.append(("nodejs", "deb", fields.get("Version", "")))
        elif path == "lib/apk/db/installed":
            try:
                text = content.decode("utf-8")
            except UnicodeError:
                raise InventoryError("invalid_package_database_encoding") from None
            for stanza in text.split("\n\n"):
                pairs = re.findall(r"^([PV]):(.*)$", stanza, re.M)
                if len({key for key, _ in pairs}) != len(pairs):
                    raise InventoryError("duplicate_package_database_field")
                fields = {key: value.rstrip("\r") for key, value in pairs}
                if fields.get("P") in {"nodejs", "nodejs-current"}:
                    found.append(("nodejs", "apk", fields.get("V", "")))
        for name, ecosystem, version in found:
            if not isinstance(version, str) or len(version) > 512:
                raise InventoryError("invalid_package_version_metadata")
            rows.append(dict(name=name, ecosystem=ecosystem, version=version, build_source="container_image_unverified",
                             path=path, layer_digest=layer, evidence_type="package_metadata", exploitability="not_tested"))
            if len(rows) > 10000:
                raise InventoryError("component_count_limit")
    return rows


def scan_archive(path, report, budget):
    stream, length = regular_input(path)
    with stream:
        index = archive_index(stream, length)
        plans = image_plans(stream, index, budget)
        for image_digest, layers, identity_kind, planning_error in plans:
            image = dict(digest=image_digest, identity_kind=identity_kind, layers=[], components=[], coverage_complete=False, notes=[])
            try:
                if planning_error:
                    raise InventoryError(planning_error)
                filesystem = {}
                for name, compressed, expected in layers:
                    offset, size, _ = index[name]
                    raw = Segment(stream, offset, size, budget)
                    decoded = gzip.GzipFile(fileobj=raw, mode="rb") if compressed else raw
                    entries, removals, opaque_dirs = layer_entries(decoded, budget, expected or "unverified")
                    if raw.remaining:
                        raise InventoryError("unconsumed_layer_bytes")
                    digest = "sha256:" + raw.digest.hexdigest()
                    if expected and digest != expected:
                        raise InventoryError("layer_digest_mismatch")
                    entries = {p: (k, c, digest) for p, (k, c, _) in entries.items()}
                    apply_layer(filesystem, entries, removals, opaque_dirs, budget)
                    validate_selected_ancestors(filesystem, entries)
                    image["layers"].append(digest)
                image["components"] = component_rows(filesystem)
                image["coverage_complete"] = True
            except InventoryError as exc:
                image["notes"].append(str(exc))
                report["complete"] = False
            except (OSError, EOFError, ValueError, zlib.error):
                image["notes"].append("image_invalid_or_unavailable")
                report["complete"] = False
            report["images"].append(image)


def scan_sbom(path, report, budget):
    stream, length = regular_input(path)
    with stream:
        if length > MAX_JSON:
            raise InventoryError("sbom_byte_limit")
        budget.add("capture", length, MAX_CAPTURE)
        raw = stream.read(length)
    data = json_value(raw)
    if not isinstance(data, dict):
        raise InventoryError("invalid_sbom")
    pending = []
    version_key = "version"
    if data.get("bomFormat") == "CycloneDX" and isinstance(data.get("specVersion"), str) and data["specVersion"] in {"1.4", "1.5", "1.6"}:
        pending.append((data.get("components", []), "components"))
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise InventoryError("invalid_sbom_metadata")
        if "component" in metadata:
            pending.append(([metadata["component"]], None))
    elif isinstance(data.get("spdxVersion"), str) and data["spdxVersion"] in {"SPDX-2.2", "SPDX-2.3"}:
        pending.append((data.get("packages", []), "packages"))
        version_key = "versionInfo"
    else:
        raise InventoryError("unsupported_sbom_format")
    rows, count = [], 0
    while pending:
        entries, prefix = pending.pop()
        if not isinstance(entries, list):
            raise InventoryError("invalid_sbom_entries")
        for index, entry in enumerate(entries):
            count += 1
            if count > 10000 or not isinstance(entry, dict):
                raise InventoryError("invalid_or_excessive_sbom_components")
            location = prefix + "/" + str(index) if prefix is not None else "metadata/component"
            name = entry.get("name", "")
            if not isinstance(name, str):
                raise InventoryError("invalid_sbom_component_name")
            group=entry.get("group","") if version_key == "version" else ""
            if not isinstance(group,str):
                raise InventoryError("invalid_sbom_component_namespace")
            if not group and name in TARGETS | {"nodejs"}:
                version = entry.get(version_key, "")
                if not isinstance(version, str) or len(version) > 512:
                    raise InventoryError("invalid_sbom_version")
                rows.append(dict(name=name, version=version, ecosystem="sbom", build_source="offline_metadata_unverified",
                                 path=location, layer_digest="", evidence_type="sbom_metadata", exploitability="not_tested"))
            if "components" in entry:
                pending.append((entry["components"], location + "/components"))
    report["sboms"].append(dict(artifact_digest="sha256:" + hashlib.sha256(raw).hexdigest(), components=rows, coverage_complete=True,
                               notes=["SBOM artifact digest is not an image or publisher identity; package metadata is not runtime attestation."]))


def export_inventory(report, consumer):
    output = _export_inventory(report, consumer)
    if consumer != "canonical":
        records = output["records"] if consumer == "sharp" else output
        maximum = 1000 if consumer == "sharp" else 10000
        byte_maximum = 16 * 1024**2 if consumer == "flowise" else 4 * 1024**2
        if len(records) > maximum or len(json.dumps(output, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False).encode("utf-8")) + 1 > byte_maximum:
            raise InventoryError("consumer_export_limit_use_canonical_or_split_inputs")
    return output


def serialized(data):
    return json.dumps(data, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n"


def content_identity(report):
    """Hash canonical evidence, excluding generation time and this digest."""
    content = {key: value for key, value in report.items() if key not in {"generated_at", "content_sha256"}}
    return hashlib.sha256(serialized(content).encode("utf-8")).hexdigest()


def generation_context(clock=None):
    value = (clock or (lambda: datetime.now(timezone.utc)))()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InventoryError("generation_clock_requires_aware_datetime")
    with regular_input(Path(__file__).resolve())[0] as stream:
        # Source identity is bounded independently of potentially large input archives.
        source = stream.read(MAX_JSON + 1)
        if len(source) > MAX_JSON:
            raise InventoryError("executable_identity_size_limit")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), hashlib.sha256(source).hexdigest()


def _export_inventory(report, consumer):
    rows = [row for image in [*report["images"], *report.get("sboms", [])] if image["coverage_complete"] for row in image["components"]]
    def version(row, maximum=512):
        value = row["version"]
        return value if len(value) <= maximum and not any(ord(c) < 32 or ord(c) == 127 for c in value) else ""
    if consumer == "canonical":
        return report
    if consumer == "sharp":
        selected = [row for row in rows if row["name"] == "sharp"]
        return {"schema_version": "1.0", "records": [{"asset_id": "metadata-" + str(i + 1), "sharp_versions": [version(r, 64)] if version(r, 64) else [], "library_source": "unknown", "sharp_build_source": "unknown"} for i, r in enumerate(selected)] or [{"asset_id": "metadata-coverage"}]}
    if consumer == "node2shell":
        selected = [row for row in rows if row["name"] == "nodejs"]
        return [{"schema_version": 1, "node_version": version(r), "build_source": "offline_metadata_unverified", "label": "metadata-node-" + str(i + 1)} for i, r in enumerate(selected)] or [{"schema_version": 1, "node_version": "", "build_source": "offline_metadata_unverified", "label": "metadata-node-coverage"}]
    selected = [row for row in rows if row["name"] in {"flowise", "flowise-components"}]
    return [{"schema_version": 1, "package": r["name"], "version": version(r), "build_source": "offline_metadata_unverified", "label": "metadata-flowise-" + str(i + 1)} for i, r in enumerate(selected)] or [{"schema_version": 1, "package": name, "version": "", "build_source": "offline_metadata_unverified", "label": "metadata-coverage"} for name in ["flowise", "flowise-components"]]


def validate_output(output, inputs, force):
    if output is None:
        return
    if not output.parent.is_dir():
        raise InventoryError("output_parent_missing")
    for source in [Path(__file__), *inputs]:
        if output.resolve() == source.resolve() or (output.exists() and source.exists() and os.path.samefile(output, source)):
            raise InventoryError("output_aliases_protected_input")
    if os.path.lexists(output) and not force:
        raise InventoryError("output_exists")
    if os.path.lexists(output) and (not output.exists() or not stat.S_ISREG(output.stat().st_mode)):
        raise InventoryError("output_not_regular")


def publish(data, output, force, state):
    text = serialized(data)
    if output is None:
        state["stdout_started"] = True
        binary = getattr(sys.stdout, "buffer", None)
        if binary is not None:
            # Receipt hashes cover these exact UTF-8 bytes, not platform text translation.
            binary.write(text.encode("utf-8"))
            binary.flush()
        else:
            # In-memory text streams used by embedders have no byte channel.
            sys.stdout.write(text)
        state["published"] = True
        return
    staged = None
    interrupted = False
    try:
        with tempfile.NamedTemporaryFile("wb", dir=output.parent, prefix=".oci-report-", delete=False) as stream:
            staged = Path(stream.name)
            stream.write(text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        state["publication_started"] = True
        if force:
            os.replace(staged, output)
        else:
            os.link(staged, output)
        state["published"] = True
    except KeyboardInterrupt:
        interrupted = True
        raise
    finally:
        if staged is not None and (not interrupted or state["published"] or not state.get("publication_started")):
            staged.unlink(missing_ok=True)


def main(argv=None, *, clock=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--archive", type=Path, help="Existing uncompressed OCI-layout or Docker-save TAR archive")
    parser.add_argument("--sbom", action="append", default=[], type=Path, help="Existing CycloneDX 1.4-1.6 or SPDX 2.2/2.3 JSON; repeatable")
    parser.add_argument("--consumer", choices=("canonical", "node2shell", "sharp", "flowise"), default="canonical", help="Optional offline consumer inventory; provenance remains unverified")
    parser.add_argument("--max-expanded-mib", type=int, default=512, help="Global expanded-byte budget, 16-4096 MiB (default 512)")
    parser.add_argument("--output", type=Path, help="New JSON report path; default stdout")
    parser.add_argument("--receipt", type=Path, help="Optional canonical receipt for a consumer export, linked by its exact SHA-256")
    parser.add_argument("--force", action="store_true", help="Replace an existing report, never a protected input")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if not args.archive and not args.sbom:
        parser.error("provide --archive or --sbom")
    if len(args.sbom) > 100:
        parser.error("at most 100 SBOM files")
    if not 16 <= args.max_expanded_mib <= 4096:
        parser.error("--max-expanded-mib must be 16 through 4096")
    if args.receipt and args.consumer == "canonical":
        parser.error("--receipt accompanies --consumer node2shell, sharp or flowise")
    report = dict(schema_version=SCHEMA_VERSION, tool={"name": "oci-runtime-inventory", "version": VERSION}, complete=True,
                  images=[], sboms=[], notes=["Offline package metadata only; no runtime, package provenance, patch state, absence or exploitability is established."],
                  exploitability="not_tested")
    report["limits"] = dict(archive_bytes=MAX_ARCHIVE, expanded_bytes=args.max_expanded_mib * 1024**2, compressed_bytes=1024**3,
                            members=MAX_MEMBERS, capture_bytes=MAX_CAPTURE, images=MAX_IMAGES, layers_per_image=MAX_LAYERS)
    budget = Budget(args.max_expanded_mib * 1024**2)
    state = {"validated": False, "published": False, "stdout_started": False, "publication_started": False}
    code = 0
    def publish_report():
        report["usage"] = {name: getattr(budget, name) for name in ["raw", "expanded", "members", "capture", "work"]}
        report["content_sha256"] = content_identity(report)
        exported = export_inventory(report, args.consumer)
        if args.receipt:
            receipt = dict(schema_version="1.0", consumer=args.consumer,
                           export_sha256=hashlib.sha256(serialized(exported).encode("utf-8")).hexdigest(), inventory=report)
            # Either artifact may survive interruption; never retry a partially published pair.
            state["publication_started"] = True
            publish(receipt, args.receipt, args.force, {"published": False, "publication_started": False})
        publish(exported, args.output, args.force, state)
    try:
        validate_output(args.output, ([args.archive] if args.archive else []) + args.sbom, args.force)
        validate_output(args.receipt, ([args.archive] if args.archive else []) + args.sbom, args.force)
        if args.output and args.receipt:
            validate_output(args.receipt, [args.output], args.force)
        generated_at, executable_sha256 = generation_context(clock)
        report["generated_at"] = generated_at
        report["tool"]["executable_sha256"] = executable_sha256
        state["validated"] = True
        try:
            if args.archive:
                scan_archive(args.archive, report, budget)
            for path in args.sbom:
                scan_sbom(path, report, budget)
        except InventoryError as exc:
            report["complete"] = False
            report["notes"].append(str(exc))
        except (OSError, EOFError, ValueError, zlib.error):
            report["complete"] = False
            report["notes"].append("input_invalid_or_unavailable")
        code = 0 if report["complete"] else 2
        publish_report()
    except KeyboardInterrupt:
        if state["validated"] and not any(state.get(key) for key in ["published", "stdout_started", "publication_started"]):
            report["complete"] = False
            report["notes"].append("interrupted_completed_images_only")
            try:
                publish_report()
            except (OSError, ValueError, KeyboardInterrupt):
                pass
        sys.stderr.write("Interrupted; output may be incomplete or publication indeterminate; no publication retry.\n")
        return 130
    except (OSError, ValueError):
        sys.stderr.write("Inventory failed: unavailable/invalid input or protected/unwritable output.\n")
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
