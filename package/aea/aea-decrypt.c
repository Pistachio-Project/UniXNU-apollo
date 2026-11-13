// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * Decrypt an Apple Encrypted Archive of profile 1 (HKDF-SHA256, AES-CTR, HMAC; symmetric key), the form of the
 * OS and cryptex disk images of an iOS 18 or later IPSW.
 *
 *   aea-decrypt IN OUT --key HEX
 *   aea-decrypt IN OUT --pem PRIVATE_KEY.pem --enc-request HEX --wrapped-key HEX
 *
 * The second form opens the archive key with HPKE (DHKEM P-256, HKDF-SHA256, AES-256-GCM) from the archive's
 * com.apple.wkms.fcs-response and the private key Apple publishes at its com.apple.wkms.fcs-key-url;
 * scripts/aea-decrypt.py reads both and calls this program.
 *
 * The container layout and key schedule follow the description in blacktop/ipsw (pkg/aea, MIT) and Apple's
 * AppleArchive documentation. Every HMAC of the archive is verified; a mismatch is fatal.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>

#include <lzfse.h>
#include "libzbitmap.h"

struct header_key {
	uint8_t mac[32];
	uint8_t key[32];
	uint8_t iv[16];
};

static void
die(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	fputs("aea-decrypt: ", stderr);
	vfprintf(stderr, format, arguments);
	fputc('\n', stderr);
	va_end(arguments);
	exit(1);
}

static void *
allocate(size_t size)
{
	void *memory = malloc(size ? size : 1);

	if (memory == NULL) {
		die("out of memory (%zu bytes)", size);
	}
	return memory;
}

static uint32_t
le32(const uint8_t *bytes)
{
	return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static uint64_t
le64(const uint8_t *bytes)
{
	return (uint64_t)le32(bytes) | (uint64_t)le32(bytes + 4) << 32;
}

static void
put_le32(uint8_t *bytes, uint32_t value)
{
	for (int i = 0; i < 4; i++) {
		bytes[i] = (uint8_t)(value >> (8 * i));
	}
}

static void
put_le64(uint8_t *bytes, uint64_t value)
{
	for (int i = 0; i < 8; i++) {
		bytes[i] = (uint8_t)(value >> (8 * i));
	}
}

static size_t
unhex(const char *text, uint8_t *out, size_t capacity)
{
	size_t length = strlen(text);

	if (length % 2 || length / 2 > capacity) {
		die("bad hex value");
	}
	for (size_t i = 0; i < length / 2; i++) {
		unsigned byte;
		if (sscanf(text + 2 * i, "%2x", &byte) != 1) {
			die("bad hex value");
		}
		out[i] = (uint8_t)byte;
	}
	return length / 2;
}

static void
read_exact(FILE *file, void *buffer, size_t length, const char *what)
{
	if (fread(buffer, 1, length, file) != length) {
		die("truncated archive (%s)", what);
	}
}

/* HKDF-SHA256 with an optional salt. */
static void
hkdf(const uint8_t *key, size_t key_length, const uint8_t *salt, size_t salt_length, const void *info, size_t info_length,
    void *out, size_t out_length)
{
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	EVP_KDF_CTX *context = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
	OSSL_PARAM parameters[5], *p = parameters;

	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, key_length);
	if (salt_length) {
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_length);
	}
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_length);
	*p = OSSL_PARAM_construct_end();
	if (context == NULL || EVP_KDF_derive(context, out, out_length, parameters) <= 0) {
		die("HKDF failed");
	}
	EVP_KDF_CTX_free(context);
	EVP_KDF_free(kdf);
}

/* HMAC-SHA256 over salt || data || le64(length of salt), the form every AEA MAC has. */
static void
aea_hmac(const uint8_t key[32], const uint8_t *data, size_t data_length, const uint8_t *salt, size_t salt_length,
    uint8_t out[32])
{
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	EVP_MAC_CTX *context = mac ? EVP_MAC_CTX_new(mac) : NULL;
	OSSL_PARAM parameters[2] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0),
		                     OSSL_PARAM_construct_end() };
	uint8_t length[8];
	size_t written = 0;

	put_le64(length, salt_length);
	if (context == NULL || !EVP_MAC_init(context, key, 32, parameters) ||
	    (salt_length && !EVP_MAC_update(context, salt, salt_length)) ||
	    !EVP_MAC_update(context, data, data_length) || !EVP_MAC_update(context, length, sizeof(length)) ||
	    !EVP_MAC_final(context, out, &written, 32) || written != 32) {
		die("HMAC failed");
	}
	EVP_MAC_CTX_free(context);
	EVP_MAC_free(mac);
}

static void
aes_ctr(const uint8_t key[32], const uint8_t iv[16], uint8_t *data, size_t length)
{
	EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
	int done = 0, tail = 0;

	if (length > INT32_MAX || context == NULL || !EVP_DecryptInit_ex(context, EVP_aes_256_ctr(), NULL, key, iv) ||
	    !EVP_DecryptUpdate(context, data, &done, data, (int)length) || !EVP_DecryptFinal_ex(context, data + done, &tail)) {
		die("AES-CTR failed");
	}
	EVP_CIPHER_CTX_free(context);
}

/* AEA's 64-bit MurmurHash2 variant. */
static uint64_t
murmur64(const uint8_t *data, size_t length)
{
	const uint64_t multiplier = 0xc6a4a7935bd1e995ull;
	uint64_t hash = 0xE2236FDC26A5F6D2ull ^ (uint64_t)length * multiplier;
	size_t tail = length & 7;

	for (; length >= 8; data += 8, length -= 8) {
		uint64_t k = le64(data) * multiplier;
		k ^= k >> 47;
		k *= multiplier;
		hash = (hash ^ k) * multiplier;
	}
	for (size_t i = 0; i < tail; i++) {
		hash ^= (uint64_t)data[i] << (8 * i);
	}
	if (tail) {
		hash *= multiplier;
	}
	hash ^= hash >> 47;
	hash *= multiplier;
	return hash ^ (hash >> 47);
}

static void
open_archive_key(const char *pem_path, const uint8_t *encapsulated, size_t encapsulated_length, const uint8_t *wrapped,
    size_t wrapped_length, uint8_t key[32])
{
	OSSL_HPKE_SUITE suite = { OSSL_HPKE_KEM_ID_P256, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_256 };
	OSSL_HPKE_CTX *context = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
	FILE *pem = fopen(pem_path, "r");
	EVP_PKEY *private_key = pem ? PEM_read_PrivateKey(pem, NULL, NULL, NULL) : NULL;
	size_t length = 32;

	if (private_key == NULL) {
		die("cannot read the private key %s", pem_path);
	}
	fclose(pem);
	if (context == NULL || OSSL_HPKE_decap(context, encapsulated, encapsulated_length, private_key, NULL, 0) != 1 ||
	    OSSL_HPKE_open(context, key, &length, NULL, 0, wrapped, wrapped_length) != 1 || length != 32) {
		die("HPKE could not open the archive key (wrong private key?)");
	}
	OSSL_HPKE_CTX_free(context);
	EVP_PKEY_free(private_key);
}

int
main(int argc, char **argv)
{
	const char *pem = NULL;
	uint8_t symmetric[32], encapsulated[256], wrapped[256];
	size_t encapsulated_length = 0, wrapped_length = 0;
	bool have_key = false;

	if (argc < 5) {
		die("usage: aea-decrypt IN OUT --key HEX | --pem FILE --enc-request HEX --wrapped-key HEX");
	}
	for (int i = 3; i + 1 < argc; i += 2) {
		if (!strcmp(argv[i], "--key")) {
			if (unhex(argv[i + 1], symmetric, sizeof(symmetric)) != 32) {
				die("--key must be 32 bytes");
			}
			have_key = true;
		} else if (!strcmp(argv[i], "--pem")) {
			pem = argv[i + 1];
		} else if (!strcmp(argv[i], "--enc-request")) {
			encapsulated_length = unhex(argv[i + 1], encapsulated, sizeof(encapsulated));
		} else if (!strcmp(argv[i], "--wrapped-key")) {
			wrapped_length = unhex(argv[i + 1], wrapped, sizeof(wrapped));
		} else {
			die("unknown option %s", argv[i]);
		}
	}
	if (!have_key) {
		if (pem == NULL || !encapsulated_length || !wrapped_length) {
			die("give --key, or --pem with --enc-request and --wrapped-key");
		}
		open_archive_key(pem, encapsulated, encapsulated_length, wrapped, wrapped_length, symmetric);
	}

	FILE *in = fopen(argv[1], "rb");
	if (in == NULL) {
		die("%s: %s", argv[1], strerror(errno));
	}
	uint8_t prologue[12];
	read_exact(in, prologue, sizeof(prologue), "header");
	uint32_t profile_word = le32(prologue + 4), auth_size = le32(prologue + 8);
	if (memcmp(prologue, "AEA1", 4) || (profile_word & 0xffffff) != 1) {
		die("%s is not an AEA archive of profile 1", argv[1]);
	}
	if (auth_size > (64u << 20)) {
		die("unreasonable auth data size");
	}
	uint8_t *auth = allocate(auth_size);
	read_exact(in, auth, auth_size, "auth data");

	uint8_t salt[32], main_key[32], info[16];
	read_exact(in, salt, sizeof(salt), "main salt");
	memcpy(info, "AEA_AMK", 7);
	put_le32(info + 7, profile_word);
	hkdf(symmetric, 32, salt, sizeof(salt), info, 11, main_key, sizeof(main_key));

	/* root header: MAC, 48 encrypted bytes, MAC of the first cluster */
	uint8_t root[112], cluster_mac[32], computed[32];
	struct header_key root_key;
	read_exact(in, root, sizeof(root), "root header");
	hkdf(main_key, 32, NULL, 0, "AEA_RHEK", 8, &root_key, sizeof(root_key));
	memcpy(cluster_mac, root + 80, 32);
	{
		/* HMAC(cluster MAC || auth data || data || le64(32 + auth size)) */
		uint8_t *salted = allocate(32 + (size_t)auth_size);
		memcpy(salted, cluster_mac, 32);
		memcpy(salted + 32, auth, auth_size);
		aea_hmac(root_key.mac, root + 32, 48, salted, 32 + (size_t)auth_size, computed);
		free(salted);
	}
	if (memcmp(computed, root, 32)) {
		die("root header HMAC mismatch: wrong key");
	}
	aes_ctr(root_key.key, root_key.iv, root + 32, 48);
	uint64_t file_size = le64(root + 32), archive_size = le64(root + 40);
	uint32_t segment_size = le32(root + 48), per_cluster = le32(root + 52);
	uint8_t compression = root[56], checksum = root[57];
	uint32_t checksum_bytes = checksum == 0 ? 0 : checksum == 1 ? 8 : checksum == 2 ? 32 : UINT32_MAX;
	if (checksum_bytes == UINT32_MAX || segment_size == 0 || segment_size > (256u << 20) || per_cluster == 0 ||
	    per_cluster > (256u << 10)) {
		die("unsupported root header (checksum %u, segment %u, %u per cluster)", checksum, segment_size, per_cluster);
	}
	(void)archive_size;

	FILE *out = fopen(argv[2], "wb");
	if (out == NULL) {
		die("%s: %s", argv[2], strerror(errno));
	}
	size_t entry_size = checksum_bytes + 8, headers_size = entry_size * per_cluster;
	size_t cluster_header_size = headers_size + 32 + 32 * (size_t)per_cluster;
	uint8_t *cluster_header = allocate(cluster_header_size);
	uint8_t *packed = allocate(segment_size), *plain = allocate((size_t)segment_size + 1);
	void *lzfse_scratch = allocate(lzfse_decode_scratch_size());
	uint64_t written = 0;

	for (uint32_t cluster = 0; written < file_size; cluster++) {
		uint8_t cluster_key[32];
		struct header_key material;

		memcpy(info, "AEA_CK", 6);
		put_le32(info + 6, cluster);
		hkdf(main_key, 32, NULL, 0, info, 10, cluster_key, sizeof(cluster_key));
		hkdf(cluster_key, 32, NULL, 0, "AEA_CHEK", 8, &material, sizeof(material));
		read_exact(in, cluster_header, cluster_header_size, "cluster header");
		uint8_t *headers = cluster_header, *macs = cluster_header + headers_size;
		aea_hmac(material.mac, headers, headers_size, macs, cluster_header_size - headers_size, computed);
		if (memcmp(computed, cluster_mac, 32)) {
			die("cluster %u HMAC mismatch", cluster);
		}
		memcpy(cluster_mac, macs, 32);
		aes_ctr(material.key, material.iv, headers, headers_size);

		for (uint32_t index = 0; index < per_cluster; index++) {
			const uint8_t *entry = headers + (size_t)index * entry_size;
			uint32_t decoded_size = le32(entry), packed_size = le32(entry + 4);
			uint64_t expected = file_size - written < segment_size ? file_size - written : segment_size;
			struct header_key segment_key;
			const uint8_t *result = packed;

			if (decoded_size != expected) {
				die("cluster %u segment %u: size %u, expected %llu", cluster, index, decoded_size,
				    (unsigned long long)expected);
			}
			if (expected == 0) {
				continue;
			}
			if (packed_size == 0 || packed_size > segment_size) {
				die("cluster %u segment %u: bad stored size %u", cluster, index, packed_size);
			}
			read_exact(in, packed, packed_size, "segment");
			memcpy(info, "AEA_SK", 6);
			put_le32(info + 6, index);
			hkdf(cluster_key, 32, NULL, 0, info, 10, &segment_key, sizeof(segment_key));
			aea_hmac(segment_key.mac, packed, packed_size, NULL, 0, computed);
			if (memcmp(computed, macs + 32 + 32 * (size_t)index, 32)) {
				die("cluster %u segment %u HMAC mismatch", cluster, index);
			}
			aes_ctr(segment_key.key, segment_key.iv, packed, packed_size);
			if (packed_size != decoded_size) {
				size_t length = 0;

				switch (compression) {
				case 'b':
					if (zbm_decompress(plain, decoded_size, packed, packed_size, &length) != 0) {
						length = 0;
					}
					break;
				case 'e':
					length = lzfse_decode_buffer(plain, (size_t)decoded_size + 1, packed, packed_size, lzfse_scratch);
					break;
				default:
					die("unsupported compression '%c'", compression);
				}
				if (length != decoded_size) {
					die("cluster %u segment %u does not decompress to %u bytes", cluster, index, decoded_size);
				}
				result = plain;
			}
			if (checksum == 1 && murmur64(result, decoded_size) != le64(entry + 8)) {
				die("cluster %u segment %u checksum mismatch", cluster, index);
			}
			if (checksum == 2) {
				uint8_t digest[32];
				size_t digest_length = 0;
				if (!EVP_Q_digest(NULL, "SHA256", NULL, result, decoded_size, digest, &digest_length) ||
				    memcmp(digest, entry + 8, 32)) {
					die("cluster %u segment %u checksum mismatch", cluster, index);
				}
			}
			if (fwrite(result, 1, decoded_size, out) != decoded_size) {
				die("%s: %s", argv[2], strerror(errno));
			}
			written += decoded_size;
		}
	}
	if (fclose(out) != 0) {
		die("%s: %s", argv[2], strerror(errno));
	}
	fprintf(stderr, "aea-decrypt: %llu bytes, compression '%c'\n", (unsigned long long)written, compression);
	return 0;
}
