/*
 * cryptoPAN.h
 *
 *  Created on: Sep 10, 2019
 *      Author: mislav
 */

#ifndef CRYPTOPAN_H_
#define CRYPTOPAN_H_

#include "openssl/evp.h"
#include "string.h"
#include "arpa/inet.h"
#include "stdio.h"

#define STATE_SIZE 64

int cryptoPAN_ipv4(uint32_t orig_addr, uint32_t *anon_addr,
		const unsigned char *m_pad, const unsigned char *key,
		const unsigned char *iv);

#endif /* CRYPTOPAN_H_ */