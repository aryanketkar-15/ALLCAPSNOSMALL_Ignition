import pytest
import os
import tempfile
import pathlib
import time
from vault.forensic_vault import ForensicVault

@pytest.fixture
def vault(tmp_path):
    return ForensicVault(vault_dir=str(tmp_path / 'snapshots'))

def test_capture_creates_files(vault):
    sid = vault.capture_snapshot({'alert_id': 'TEST-001'})
    json_path = vault.vault_dir / f"vault_{sid}.json"
    hash_path = vault.vault_dir / f"vault_{sid}.sha256"
    assert json_path.exists()
    assert hash_path.exists()

def test_hash_is_64_hex_chars(vault):
    sid = vault.capture_snapshot({'alert_id': 'TEST-002'})
    hash_path = vault.vault_dir / f"vault_{sid}.sha256"
    stored_hash = hash_path.read_text(encoding='utf-8').strip()
    assert len(stored_hash) == 64
    assert stored_hash.isalnum()

def test_integrity_pass_on_clean_snapshot(vault):
    sid = vault.capture_snapshot({'alert_id': 'TEST-003'})
    assert vault.verify_integrity(sid) is True

def test_integrity_fail_on_tampered_snapshot(vault):
    sid = vault.capture_snapshot({'alert_id': 'TEST-004'})
    json_path = vault.vault_dir / f"vault_{sid}.json"
    with open(json_path, 'ab') as f:
        f.write(b'X')
    assert vault.verify_integrity(sid) is False

def test_chain_of_custody_contains_hash(vault):
    sid = vault.capture_snapshot({'alert_id': 'TEST-005'})
    coc = vault.generate_chain_of_custody(sid)
    hash_path = vault.vault_dir / f"vault_{sid}.sha256"
    stored_hash = hash_path.read_text(encoding='utf-8').strip()
    assert stored_hash in coc

def test_duplicate_alert_ids_do_not_collide(vault):
    sid1 = vault.capture_snapshot({'alert_id': 'TEST-006', 'data': 'A'})
    time.sleep(0.001)  # Guarantee timestamp differentiation
    sid2 = vault.capture_snapshot({'alert_id': 'TEST-006', 'data': 'B'})
    
    assert sid1 != sid2
    files = list(vault.vault_dir.glob("vault_*.json"))
    assert len(files) == 2
