#ifndef MYCRYPTO_H
#define MYCRYPTO_H

#include "aes.h"
#include "gcm.h"

operation_result encryption (const unsigned char *key,
	const unsigned char *iv,
    size_t iv_len,
    const unsigned char *add,
    size_t add_len,
    const unsigned char *input,
    size_t length,
    unsigned char *output,
    unsigned char *tag,
    size_t tag_len);

operation_result decryption (const unsigned char *key,
    	const unsigned char *iv,
        size_t iv_len,
        const unsigned char *add,
        size_t add_len,
        const unsigned char *tag,
        size_t tag_len,
        const unsigned char *input,
        size_t length,
        unsigned char *output );

#endif
