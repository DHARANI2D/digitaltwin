# agents/artifact_agent.py

import os
import zipfile
import hashlib
import csv
import json
from .base import BaseAgent
from db_helper import DatabaseHelper

class ArtifactAgent(BaseAgent):
    """
    Ingests raw parsed artifacts (CSVs, JSONs) and normalizes them into 
    the DFIRState. Performs initial hash validation for chain of custody.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print(f"[ArtifactAgent] Ingesting evidence for case: '{state.case_id}' from path: '{state.evidence_path}'")
        
        db = DatabaseHelper()
        
        # If it's a zip file, extract it to a directory named after case_id in the same folder
        extract_dir = state.evidence_path
        if os.path.isfile(state.evidence_path) and state.evidence_path.endswith(".zip"):
            extract_dir = os.path.join(os.path.dirname(state.evidence_path), f"extracted_{state.case_id}")
            print(f"[ArtifactAgent] Extracting ZIP to: {extract_dir}")
            with zipfile.ZipFile(state.evidence_path, "r") as zip_ref:
                zip_ref.extractall(extract_dir)

        # 1. Look for case_meta.json
        meta_path = os.path.join(extract_dir, "case_meta.json")
        hostname = "unknown-host"
        username = "system"
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r") as f:
                    meta_data = json.load(f)
                    if not state.case_id:
                        state.case_id = meta_data.get("case_id", "CASE-UNKNOWN")
                    hostname = meta_data.get("hostname", hostname)
                    username = meta_data.get("username", username)
                    print(f"[ArtifactAgent] Loaded metadata: Hostname={hostname}, Operator={username}")
            except Exception as e:
                print(f"[ArtifactAgent] Failed to read case_meta.json: {e}")

        # Insert/Update case in Database
        db.insert_case(state.case_id, state.evidence_path)

        # 2. Hash Validation (Chain of Custody)
        manifest_path = os.path.join(extract_dir, "artifact_manifest.csv")
        if os.path.exists(manifest_path):
            print("[ArtifactAgent] Verifying artifact manifest hashes...")
            verified_all = True
            with open(manifest_path, mode="r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    file_name = row.get("file_name")
                    expected_hash = row.get("sha256")
                    actual_file_path = os.path.join(extract_dir, file_name)
                    if os.path.exists(actual_file_path):
                        sha256_hash = hashlib.sha256()
                        with open(actual_file_path, "rb") as bf:
                            for byte_block in iter(lambda: bf.read(4096), b""):
                                sha256_hash.update(byte_block)
                        actual_hash = sha256_hash.hexdigest()
                        if actual_hash == expected_hash:
                            print(f"[ArtifactAgent] Integrity verified: {file_name}")
                        else:
                            print(f"[ArtifactAgent] INTEGRITY FAILURE for file {file_name}! Expected: {expected_hash}, Got: {actual_hash}")
                            verified_all = False
                    else:
                        print(f"[ArtifactAgent] Warning: Manifest file listed but not found: {file_name}")
            if verified_all:
                print("[ArtifactAgent] Cryptographic integrity chain of custody successfully verified.")
            else:
                print("[ArtifactAgent] INTEGRITY CHECK ENCOUNTERED WARNINGS/ERRORS.")

        # 3. Load Event Logs (evtx_events.json / prefetch.json / etc.)
        # In a real environment we read actual logs. Here we handle JSON files
        # representing the forensic outputs from PECmd, EvtxECmd, etc.
        self._load_evtx_records(extract_dir, state, db, hostname, username)
        self._load_prefetch_records(extract_dir, state, db)
        self._load_registry_records(extract_dir, state, db)
        self._load_mft_records(extract_dir, state, db)
        self._load_memory_records(extract_dir, state, db)

        print(f"[ArtifactAgent] Ingested: {len(state.evtx_events)} EVTX events, {len(state.prefetch_records)} Prefetch records.")
        return state

    def _load_evtx_records(self, extract_dir, state, db, hostname, username):
        evtx_json = os.path.join(extract_dir, "evtx_events.json")
        if os.path.exists(evtx_json):
            try:
                with open(evtx_json, "r") as f:
                    records = json.load(f)
                    for r in records:
                        # Append metadata if not set
                        if "hostname" not in r: r["hostname"] = hostname
                        if "username" not in r: r["username"] = username
                        state.evtx_events.append(r)
                        db.insert_event(state.case_id, r.get("timestamp"), "EVTX", r.get("event_type", "Process"), r)
            except Exception as e:
                print(f"[ArtifactAgent] Error parsing evtx_events.json: {e}")

    def _load_prefetch_records(self, extract_dir, state, db):
        pref_json = os.path.join(extract_dir, "prefetch_records.json")
        if os.path.exists(pref_json):
            try:
                with open(pref_json, "r") as f:
                    records = json.load(f)
                    for r in records:
                        state.prefetch_records.append(r)
                        db.insert_event(state.case_id, r.get("last_run"), "Prefetch", "Execution", r)
            except Exception as e:
                print(f"[ArtifactAgent] Error parsing prefetch_records.json: {e}")

    def _load_registry_records(self, extract_dir, state, db):
        reg_json = os.path.join(extract_dir, "registry_keys.json")
        if os.path.exists(reg_json):
            try:
                with open(reg_json, "r") as f:
                    records = json.load(f)
                    for r in records:
                        state.registry_keys.append(r)
                        db.insert_event(state.case_id, r.get("last_write"), "Registry", "Key", r)
            except Exception as e:
                print(f"[ArtifactAgent] Error parsing registry_keys.json: {e}")

    def _load_mft_records(self, extract_dir, state, db):
        mft_json = os.path.join(extract_dir, "mft_records.json")
        if os.path.exists(mft_json):
            try:
                with open(mft_json, "r") as f:
                    records = json.load(f)
                    for r in records:
                        state.mft_records.append(r)
                        db.insert_event(state.case_id, r.get("timestamp"), "MFT", "FileActivity", r)
            except Exception as e:
                print(f"[ArtifactAgent] Error parsing mft_records.json: {e}")

    def _load_memory_records(self, extract_dir, state, db):
        mem_json = os.path.join(extract_dir, "memory_findings.json")
        if os.path.exists(mem_json):
            try:
                with open(mem_json, "r") as f:
                    records = json.load(f)
                    for r in records:
                        state.memory_findings.append(r)
                        db.insert_event(state.case_id, r.get("timestamp"), "Memory", "VolatilityPlugin", r)
            except Exception as e:
                print(f"[ArtifactAgent] Error parsing memory_findings.json: {e}")
