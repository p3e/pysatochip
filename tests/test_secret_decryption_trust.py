#!/usr/bin/env python3
"""Trust-boundary regressions for encrypted SeedKeeper JSON backups."""

import copy
import hashlib
import hmac
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pysatochip import ec_backend
from pysatochip.SecretDecryption import (
    BACKUP_FORMAT_VERSION,
    Decrypt_Secret,
    SECRET_CST_SC,
    export_data_hash,
)


IMPORTER_PRIVATE_KEY = bytes.fromhex("11" * 32)
EXPORTER_PRIVATE_KEY = bytes.fromhex("22" * 32)
ATTACKER_PRIVATE_KEY = bytes.fromhex("33" * 32)


def build_export(exporter_private_key=EXPORTER_PRIVATE_KEY,
                 secret_data=b"\x04seed"):
    importer_pubkey = ec_backend.privkey_to_pubkey(
        IMPORTER_PRIVATE_KEY, compressed=False)
    exporter_pubkey = ec_backend.privkey_to_pubkey(
        exporter_private_key, compressed=False)
    shared_secret = ec_backend.ecdh_shared_x(
        exporter_private_key, importer_pubkey)
    encryption_key = hmac.new(
        shared_secret, SECRET_CST_SC[:6], hashlib.sha1).digest()[:-4]
    hmac_key = hmac.new(
        shared_secret, SECRET_CST_SC[6:], hashlib.sha1).digest()

    fingerprint = hashlib.sha256(secret_data).digest()[:4]
    label = b"wallet"
    header = bytes([
        0x00, 0x01,              # secret id
        0x10, 0x01, 0x02,       # type, origin, export rights
        0x00, 0x01, 0x01,       # export counters
    ]) + fingerprint + bytes([
        0x00, 0x00, len(label),  # rfu1, rfu2, label length
    ]) + label

    pad_size = algorithms.AES.block_size // 8 - (
        len(secret_data) % (algorithms.AES.block_size // 8))
    padded_secret = secret_data + bytes([pad_size]) * pad_size
    iv = bytes(range(algorithms.AES.block_size // 8))
    encryptor = Cipher(
        algorithms.AES(encryption_key), modes.CBC(iv),
        backend=default_backend()).encryptor()
    ciphertext = encryptor.update(padded_secret) + encryptor.finalize()

    hashed_secret = hashlib.sha256(header[2:14] + ciphertext).digest()
    secret_hmac = hmac.new(hmac_key, hashed_secret, hashlib.sha1).digest()
    return {
        "format_version": BACKUP_FORMAT_VERSION,
        "authentikey_exporter": exporter_pubkey.hex(),
        "authentikey_importer": importer_pubkey.hex(),
        "secrets": [{
            "label": label.decode(),
            "type": header[2],
            "origin": header[3],
            "export_rights": header[4],
            "rfu1": header[12],
            "rfu2": header[13],
            "fingerprint": fingerprint.hex(),
            "header": header.hex(),
            "iv": iv.hex(),
            "secret_encrypted": ciphertext.hex(),
            "hmac": secret_hmac.hex(),
        }],
    }


class TestSecretDecryptionTrust(unittest.TestCase):

    def test_valid_backup_accepts_trusted_compressed_exporter(self):
        export_data = build_export()
        trusted_exporter = ec_backend.privkey_to_pubkey(
            EXPORTER_PRIVATE_KEY, compressed=True).hex()

        secrets = Decrypt_Secret(
            IMPORTER_PRIVATE_KEY.hex(),
            export_data,
            trusted_exporter,
            export_data_hash(export_data),
        )

        self.assertEqual(secrets[0]["label"], "wallet")
        self.assertEqual(secrets[0]["decryped_secret"], "seed")

    def test_recomputed_attacker_export_rejects_wrong_identity(self):
        forged_export = build_export(
            exporter_private_key=ATTACKER_PRIVATE_KEY,
            secret_data=b"\x04evil",
        )
        trusted_exporter = ec_backend.privkey_to_pubkey(
            EXPORTER_PRIVATE_KEY, compressed=False).hex()

        with self.assertRaisesRegex(ValueError, "trusted exporter"):
            Decrypt_Secret(
                IMPORTER_PRIVATE_KEY.hex(),
                forged_export,
                trusted_exporter,
                export_data_hash(forged_export),
            )

    def test_envelope_commitment_rejects_iv_and_metadata_changes(self):
        export_data = build_export()
        expected_hash = export_data_hash(export_data)
        trusted_exporter = export_data["authentikey_exporter"]

        changed_iv = copy.deepcopy(export_data)
        changed_iv["secrets"][0]["iv"] = "ff" + changed_iv["secrets"][0]["iv"][2:]
        changed_metadata = copy.deepcopy(export_data)
        changed_metadata["secrets"][0]["label"] = "attacker wallet"

        for changed_export in (changed_iv, changed_metadata):
            with self.subTest(changed_export=changed_export):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    Decrypt_Secret(
                        IMPORTER_PRIVATE_KEY.hex(),
                        changed_export,
                        trusted_exporter,
                        expected_hash,
                    )

    def test_legacy_backup_without_version_remains_supported(self):
        export_data = build_export()
        del export_data["format_version"]

        secrets = Decrypt_Secret(
            IMPORTER_PRIVATE_KEY.hex(),
            export_data,
            export_data["authentikey_exporter"],
            export_data_hash(export_data),
        )

        self.assertEqual(secrets[0]["decryped_secret"], "seed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
