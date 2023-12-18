/*
 * This is a modification of the original cryptoPAN developed by Jinliang Fan
 * And presented in the paper Prefix-preserving IP address anonymization:
 * measurement-based security evaluation and a new cryptographic scheme
 *
 * CryptoPAN sources are hard to track down, but the April 17, 2002 version of panonymizer.cpp can still be found
 * in the source files for pktanon HERE: https://www.tm.uka.de/software/pktanon/download/index.html
 */

#include "cryptoPAN.h"

int cryptoPAN_ipv4(uint32_t orig_addr, uint32_t *anon_addr,
		const unsigned char *m_pad, const unsigned char *key,
		const unsigned char *iv) {
	uint8_t rin_output[16];
	uint8_t rin_input[16];

	int len;

	uint32_t result = 0;
	uint32_t first4bytes_pad, first4bytes_input;
	int pos;

	EVP_CIPHER_CTX *ctx;

	//Initialize context
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	//Disable padding. Since we're providing our own static pad. If this were on we'd end up with inconsistent output
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	//Initialize encryption
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	orig_addr = ntohl(orig_addr);

	memcpy(rin_input, m_pad, 16);
	first4bytes_pad = (((uint32_t) m_pad[0]) << 24)
			+ (((uint32_t) m_pad[1]) << 16) + (((uint32_t) m_pad[2]) << 8)
			+ (uint32_t) m_pad[3];

	// For each prefixes with length from 0 to 31, generate a bit using the Rijndael cipher,
	// which is used as a pseudorandom function here. The bits generated in every rounds
	// are combineed into a pseudorandom one-time-pad.
	for (pos = 0; pos <= 31; pos++) {

		//Padding: The most significant pos bits are taken from orig_addr. The other 128-pos
		//bits are taken from m_pad. The variables first4bytes_pad and first4bytes_input are used
		//to handle the annoying byte order problem.
		if (pos == 0) {
			first4bytes_input = first4bytes_pad;
		} else {
			first4bytes_input = ((orig_addr >> (32 - pos)) << (32 - pos))
					| ((first4bytes_pad << pos) >> pos);
		}
		rin_input[0] = (uint8_t) (first4bytes_input >> 24);
		rin_input[1] = (uint8_t) ((first4bytes_input << 8) >> 24);
		rin_input[2] = (uint8_t) ((first4bytes_input << 16) >> 24);
		rin_input[3] = (uint8_t) ((first4bytes_input << 24) >> 24);

		//Encryption: The Rijndael cipher is used as pseudorandom function. During each
		//round, only the first bit of rin_output is used.
		//Here the original call to m_rin.blockEncrypt is replaced with a call to EVP_EncryptUpdate which is the
		//encryption function from OpenSSLs libcrypto.

		if (1 != EVP_EncryptUpdate(ctx, rin_output, &len, rin_input, 16)) {
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		//Combination: the bits are combined into a pseudorandom one-time-pad
		result |= (rin_output[0] >> 7) << (31 - pos);
	}
	//XOR the orginal address with the pseudorandom one-time-pad
	*anon_addr = result ^ orig_addr;
	*anon_addr = htonl(*anon_addr);

	EVP_CIPHER_CTX_free(ctx);
	return 1;
}

