#ifndef DATABASE_H
#define DATABASE_H

// #include "sample_libcrypto.h"
#include "remote_attestation.h"

typedef struct _sp_db_item_t
{
    sample_ec_pub_t             g_a;
    sample_ec_pub_t             g_b;
    sample_ec_key_128bit_t      vk_key;// Shared secret key for the REPORT_DATA
    sample_ec_key_128bit_t      mk_key;// Shared secret key for generating MAC's
    sample_ec_key_128bit_t      sk_key;// Shared secret key for encryption
    sample_ec_key_128bit_t      smk_key;// Used only for SIGMA protocol
    sample_ec_priv_t            b;
    sample_ps_sec_prop_desc_t   ps_sec_prop;
}sp_db_item_t;

#endif//DATABASE_H
