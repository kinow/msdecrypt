/*
 * Created based on mapserver code, specially mapcrypto.h. It uses the given key
 * to try to decrypt a value.
 *
 * @see https://github.com/mapserver/mapserver/blob/9ade01a09ee896b1bf43d33728acafb67e122f93/mapcrypto.c
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>   /* rand() */
#include <time.h>     /* time() */
#include <string.h>

#define MS_TRUE 1 /* logical control variables */
#define MS_FALSE 0
#define MS_UNKNOWN -1
#define MS_ON 1
#define MS_OFF 0
#define MS_DEFAULT 2
#define MS_EMBED 3
#define MS_DELETE 4
#define MS_YES 1
#define MS_NO 0

/* definition of  ms_int32/ms_uint32 */
#include <limits.h>
#ifndef _WIN32
#include <stdint.h>
#endif

#ifdef _WIN32
#ifndef SIZE_MAX
#ifdef _WIN64
#define SIZE_MAX _UI64_MAX
#else
#define SIZE_MAX UINT_MAX
#endif
#endif
#endif

#if ULONG_MAX == 0xffffffff
typedef long ms_int32;
typedef unsigned long ms_uint32;
#elif UINT_MAX == 0xffffffff
typedef int ms_int32;
typedef unsigned int ms_uint32;
#else
typedef int32_t ms_int32;
typedef uint32_t ms_uint32;
#endif

#define MS_ENCRYPTION_KEY_SIZE  16   /* Key size: 128 bits = 16 bytes */
enum MS_RETURN_VALUE {
	MS_SUCCESS, MS_FAILURE, MS_DONE
};

void decipher(const ms_uint32 * const v, ms_uint32 * const w,
		const ms_uint32 * const k) {
	register ms_uint32 y = v[0], z = v[1], sum = 0xC6EF3720, delta = 0x9E3779B9,
			n = 32;

	/* sum = delta<<5, in general sum = delta * n */

	while (n-- > 0) {
		z -= ((y << 4 ^ y >> 5) + y) ^ (sum + k[sum >> 11 & 3]);
		sum -= delta;
		y -= ((z << 4 ^ z >> 5) + z) ^ (sum + k[sum & 3]);
	}

	w[0] = y;
	w[1] = z;
}

void msHexEncode(const unsigned char *in, char *out, int numbytes) {
	char const *hex = "0123456789ABCDEF";

	while (numbytes-- > 0) {
		*out++ = hex[*in / 16];
		*out++ = hex[*in % 16];
		in++;
	}
	*out = '\0';
}

int msHexDecode(const char *in, unsigned char *out, int numchars) {
	int numbytes_out = 0;

	/* Make sure numchars is even */
	numchars = (numchars / 2) * 2;

	if (numchars < 2)
		numchars = -1; /* Will result in this value being ignored in the loop*/

	while (*in != '\0' && *(in + 1) != '\0' && numchars != 0) {
		*out = 0x10 * (*in >= 'A' ? ((*in & 0xdf) - 'A') + 10 : (*in - '0'));
		in++;
		*out += (*in >= 'A' ? ((*in & 0xdf) - 'A') + 10 : (*in - '0'));
		in++;

		out++;
		numbytes_out++;

		numchars -= 2;
	}

	return numbytes_out;
}

void msDecryptStringWithKey(const unsigned char *key, const char *in,
		char *out) {
	ms_uint32 v[4], w[4];
	const ms_uint32 *k;
	int last_block = MS_FALSE;

	/* Casting the key this way is safe only as long as longs are 4 bytes
	 * on this platform */
	assert(sizeof(ms_uint32) == 4);
	k = (const ms_uint32 *) key;

	while (!last_block) {
		int i;
		/* decipher() takes v[2] (64 bits) as input.
		 * Copy bytes from in[] to the v[2] input array (pair of 4 bytes)
		 * v[] is padded with zeros if string doesn't align with 8 bytes
		 */
		v[0] = 0;
		v[1] = 0;

		if (msHexDecode(in, (unsigned char *) v, 8) != 4)
			last_block = MS_TRUE;
		else {
			in += 8;
			if (msHexDecode(in, (unsigned char *) (v + 1), 8) != 4)
				last_block = MS_TRUE;
			else
				in += 8;
		}

		/* Do the actual decryption */
		decipher(v, w, k);

		/* Copy the results to out[] */
		for (i = 0; i < 2; i++) {
			*out++ = (w[i] & 0x000000ff);
			*out++ = (w[i] & 0x0000ff00) >> 8;
			*out++ = (w[i] & 0x00ff0000) >> 16;
			*out++ = (w[i] & 0xff000000) >> 24;
		}

		if (*in == '\0')
			last_block = MS_TRUE;
	}

	/* Make sure output is 0-terminated */
	*out = '\0';
}

int msReadEncryptionKeyFromFile(const char *keyfile, unsigned char *k) {
	FILE *fp;
	char szBuf[100];
	int numchars;

	if ((fp = fopen(keyfile, "rt")) == NULL) {
		return MS_FAILURE;
	}

	numchars = fread(szBuf, sizeof(unsigned char), MS_ENCRYPTION_KEY_SIZE * 2,
			fp);
	fclose(fp);
	szBuf[MS_ENCRYPTION_KEY_SIZE * 2] = '\0';

	if (numchars != MS_ENCRYPTION_KEY_SIZE * 2) {
		return MS_FAILURE;
	}

	msHexDecode(szBuf, k, MS_ENCRYPTION_KEY_SIZE * 2);

	return MS_SUCCESS;
}

int main(int argc, char **argv) {

	if (argc != 3) {
		printf("Usage:\tmsdecrypt <key> <secret>\n");
		return -1;
	}

	unsigned char encryption_key[MS_ENCRYPTION_KEY_SIZE * 2 + 1];
	char string_buf[256], string_buf2[256];

	if (msReadEncryptionKeyFromFile(argv[1],
			encryption_key) != MS_SUCCESS) {
		printf("msReadEncryptionKeyFromFile() = MS_FAILURE\n");
		printf("Aborting program!\n");
		return -1;
	} else {
		msHexEncode(encryption_key, string_buf, MS_ENCRYPTION_KEY_SIZE);
		printf("KEY => '%s'\n", string_buf);
	}

	msDecryptStringWithKey(encryption_key, argv[2], string_buf2);
	printf("INPUT '%s' DECRYPTED AS '%s'\n", string_buf, string_buf2);
}

