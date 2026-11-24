#!/usr/bin/env python3
#
# Copyright (c) 2023 Stephen Rothery - https://github.com/3rdIteration
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import binascii, json, hmac, hashlib, argparse, logging

import cryptography
from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers import Cipher as CG_Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as CG_algorithms
from cryptography.hazmat.primitives.ciphers import modes as CG_modes
from cryptography.hazmat.backends import default_backend as CG_default_backend

from pysatochip import ec_backend
from pysatochip.ecc import ECPubkey, InvalidECPointException
from pysatochip.JCconstants import *

logger = logging.getLogger(__name__)
# NB: no basicConfig()/setLevel() at import time -- this module is importable as
# part of the pysatochip package, and configuring the root logger there would
# hijack the logging setup of whatever application imported us. Both belong in
# __main__, below, where this file is used as a standalone script.

SECRET_CST_SC = b"seckeysecmac"
BACKUP_FORMAT_VERSION = 1
AES_BLOCK_SIZE = CG_algorithms.AES.block_size // 8


def _build_arg_parser():
	parser = argparse.ArgumentParser(description='Decrypt Encrypted JSON Exports from Seedkeeper')
	parser.add_argument('--privkey', required = True,
					help="Private key to attempt decryption of the encrypted secret. (In raw hex format)")
	parser.add_argument('--secret-json-file', required = True,
					help="Path to file containing encrypted secret(s) in JSON format")
	parser.add_argument('--authentikey-exporter', required = True,
					help="Trusted exporter authentikey obtained independently of the JSON backup")
	parser.add_argument('--backup-sha256', required = True,
					help="SHA-256 commitment recorded when the backup was created")
	return parser

def export_data_hash(export_data):
	"""Return the canonical SHA-256 commitment for an export dictionary.

	The result is only an authenticity check when it is recorded at export time
	and supplied independently of the JSON being decrypted.
	"""
	canonical_export = json.dumps(
		export_data,
		sort_keys=True,
		separators=(',', ':'),
		ensure_ascii=False,
		allow_nan=False,
	).encode('utf-8')
	return hashlib.sha256(canonical_export).hexdigest()


def _parse_pubkey(pubkey_hex, description):
	try:
		pubkey = bytes.fromhex(pubkey_hex)
		return ECPubkey(pubkey).get_public_key_bytes(compressed=False)
	except (TypeError, ValueError, AssertionError, InvalidECPointException) as exc:
		# ECPubkey raises repository-specific point/encoding exceptions in
		# addition to ValueError. Keep the public error independent of backend.
		raise ValueError("Invalid {}".format(description)) from exc


def _parse_sha256(digest_hex):
	try:
		digest = bytes.fromhex(digest_hex)
	except (TypeError, ValueError) as exc:
		raise ValueError("Backup SHA-256 must be a 64-character hex string") from exc
	if len(digest) != hashlib.sha256().digest_size:
		raise ValueError("Backup SHA-256 must be a 64-character hex string")
	return digest


def unpad(s):
	"""Remove and validate the SeedKeeper export's PKCS#7 padding."""
	if not s or len(s) % AES_BLOCK_SIZE:
		raise ValueError("Decrypted secret has invalid padding")
	pad_size = s[-1]
	if pad_size < 1 or pad_size > AES_BLOCK_SIZE:
		raise ValueError("Decrypted secret has invalid padding")
	if not hmac.compare_digest(s[-pad_size:], bytes([pad_size]) * pad_size):
		raise ValueError("Decrypted secret has invalid padding")
	return s[:-pad_size]

# The trusted exporter key and backup commitment must come from outside the
# backup. Values copied from export_data do not authenticate attacker-controlled
# JSON and would reintroduce exporter-key substitution.
def Decrypt_Secret(privateKey, export_data, trusted_exporter_pubkey, expected_backup_sha256):
	"""Decrypt an export after checking its independently trusted identity.

	``trusted_exporter_pubkey`` identifies the SeedKeeper that created the
	backup. ``expected_backup_sha256`` is the commitment printed at export time;
	it binds every JSON field, including the IV and duplicated metadata that the
	on-card legacy HMAC does not cover.
	"""
	decrypted_secrets = []

	# Verify the complete envelope before using any attacker-controlled key or
	# metadata. Hash the parsed object so insignificant JSON formatting changes
	# do not invalidate an otherwise identical backup.
	expected_hash = _parse_sha256(expected_backup_sha256)
	computed_hash = bytes.fromhex(export_data_hash(export_data))
	if not hmac.compare_digest(computed_hash, expected_hash):
		raise ValueError("Backup SHA-256 mismatch: the export is not the trusted backup")

	format_version = export_data.get('format_version', BACKUP_FORMAT_VERSION)
	if type(format_version) is not int or format_version != BACKUP_FORMAT_VERSION:
		raise ValueError("Unsupported SeedKeeper backup format version")

	# Load Key & Generate Shared Secret.
	# This is a long-term user private key, so the scalar multiplication has to
	# happen in a side-channel-hardened backend (issue #8 / CVE-2024-23342).
	privkey_bytes = binascii.unhexlify(privateKey)
	generated_pubkey = ec_backend.privkey_to_pubkey(privkey_bytes, compressed=False)
	importer_pubkey = _parse_pubkey(export_data['authentikey_importer'], "importer authentikey")
	if not hmac.compare_digest(generated_pubkey, importer_pubkey):
		raise Exception("Derived Public Key doesn't match Required Public Key...")

	exporter_pubkey = _parse_pubkey(export_data['authentikey_exporter'], "exporter authentikey")
	trusted_exporter = _parse_pubkey(trusted_exporter_pubkey, "trusted exporter authentikey")
	if not hmac.compare_digest(exporter_pubkey, trusted_exporter):
		raise ValueError("Backup exporter authentikey does not match the trusted exporter")
	shared_secret = ec_backend.ecdh_shared_x(privkey_bytes, exporter_pubkey)

	#Generate keys for decryption and mac
	decryption_key = hmac.new(shared_secret, msg = SECRET_CST_SC[:6], digestmod = hashlib.sha1).digest()[:-4]
	hmac_key = hmac.new(shared_secret, msg = SECRET_CST_SC[6:], digestmod = hashlib.sha1).digest()

	for secret in export_data['secrets']:
		exported_iv = bytes.fromhex(secret['iv'])
		exported_hmac = bytes.fromhex(secret['hmac'])
		exported_secret_data = bytes.fromhex(secret['secret_encrypted'])
		full_header = bytes.fromhex(secret['header'])
		if len(exported_iv) != AES_BLOCK_SIZE:
			raise ValueError("Encrypted secret has an invalid IV length")
		if not exported_secret_data or len(exported_secret_data) % AES_BLOCK_SIZE:
			raise ValueError("Encrypted secret has an invalid ciphertext length")
		if len(full_header) < 15 or len(full_header) != 15 + full_header[14]:
			raise ValueError("Encrypted secret has an invalid header")
		export_header = full_header[2:(2+12)] # sid (first two bytes), label and labelsize aren't part of the legacy HMAC

		# Compute and check MAC
		hashed_secret_data = hashlib.sha256()
		hashed_secret_data.update(export_header)
		hashed_secret_data.update(exported_secret_data)
		computed_mac = hmac.new(hmac_key, hashed_secret_data.digest(), digestmod = hashlib.sha1).digest()

		if not hmac.compare_digest(computed_mac, exported_hmac):
			raise Exception("WARNING: MAC Mismatch (Encrypted Data is invalid, tampered or corrupt)")

		# Decrypt Secret
		cipher = CG_Cipher(CG_algorithms.AES(decryption_key), CG_modes.CBC(exported_iv), backend=CG_default_backend())
		decryptor = cipher.decryptor()
		raw_secret = decryptor.update(exported_secret_data) + decryptor.finalize()
		secret_data = unpad(raw_secret)

		# This card-generated fingerprint is part of the legacy HMAC input. It
		# provides a second check that the decrypted, unpadded bytes are the secret
		# the exporter committed to, rather than merely valid CBC plaintext.
		computed_fingerprint = hashlib.sha256(secret_data).digest()[:4]
		if not hmac.compare_digest(computed_fingerprint, full_header[8:12]):
			raise ValueError("Decrypted secret fingerprint does not match its authenticated header")

		try: # First just try for text based secrets like mnemonics or general password
			decrypted_secret = secret_data.split(b'\x00')[0][1:].decode()
		except UnicodeDecodeError: # Then try to treat as hex encoded secrets
			decrypted_secret = secret_data.hex()[2:]

		# Keep the historical presentation fields. They are now covered by the
		# independently recorded whole-envelope commitment.
		label = secret['label']
		type = SEEDKEEPER_DIC_TYPE.get(secret['type'], hex(secret['type']))

		decrypted_secrets.append({"label" : label, "type" : type, "decryped_secret" : decrypted_secret})

	return decrypted_secrets

if __name__ == '__main__':
	logging.basicConfig(level=logging.ERROR, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
	args = _build_arg_parser().parse_args()
	# Opening JSON and loading file
	f = open(args.secret_json_file)
	export_data = json.load(f)

	try:
		secrets = Decrypt_Secret(
			args.privkey,
			export_data,
			args.authentikey_exporter,
			args.backup_sha256,
		)
		for secret in secrets:
			print(secret)
	except Exception as e:
		print("FAILED:", e)
