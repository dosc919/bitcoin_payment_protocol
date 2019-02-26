//
// Created by dominik on 28.09.17.
//

#include <openssl/kdf.h>
#include "gtest/gtest.h"

extern "C"
{
#include <openssl/evp.h>
#include "data_structures.h"
#include "const_and_error.h"
#include "daps.h"
}

#define NUM_ADDRESSES (10)

TEST(key_gen_check, test_population)
{
    DapsPK* pk = dapsPkNew();
    ASSERT_TRUE(pk != NULL);

    DapsSK* sk = dapsSkNew();
    ASSERT_TRUE(sk != NULL);

    uint32_t n = NUM_ADDRESSES;

    ErrorCodes error;
    ASSERT_EQ(error = dapsKeyGen(sk, pk, n), SUCCESS) << getErrorString(error);

    ASSERT_TRUE(pk != NULL);
    ASSERT_TRUE(sk != NULL);

    EXPECT_TRUE(pk->pk_sign_ != NULL);
    EXPECT_TRUE(pk->pk_enc_ != NULL);
    EXPECT_TRUE(pk->y_);
    EXPECT_TRUE(pk->n_ != 0);
    ASSERT_TRUE(pk->c1_i_ != NULL);
    ASSERT_TRUE(pk->c2_i_ != NULL);

    for(int i = 0; i < pk->n_; ++i)
    {
        EXPECT_TRUE(pk->c1_i_[i] != NULL);
        EXPECT_TRUE(pk->c2_i_[i] != NULL);
    }

    EXPECT_TRUE(sk->sk_sign_ != NULL);
    EXPECT_TRUE(sk->n_ != 0);
    ASSERT_TRUE(sk->r_i_ != NULL);
    ASSERT_TRUE(sk->rho_i_ != NULL);

    for(int i = 0; i < sk->n_; ++i)
    {
        EXPECT_TRUE(sk->r_i_[i] != NULL);
        EXPECT_TRUE(sk->rho_i_[i] != NULL);
    }

    dapsPkFree(&pk);
    dapsSkFree(&sk);
}

TEST(key_gen_check, test_pk_null)
{
    DapsPK* pk = NULL;

    DapsSK* sk = dapsSkNew();
    ASSERT_TRUE(sk != NULL);

    uint32_t n = NUM_ADDRESSES;

    ErrorCodes error;
    EXPECT_EQ(error = dapsKeyGen(sk, pk, n), PK_NULL) << getErrorString(error);

    EXPECT_TRUE(pk == NULL);
    EXPECT_TRUE(sk != NULL);

    dapsSkFree(&sk);
}

TEST(key_gen_check, test_sk_null)
{
    DapsPK* pk = dapsPkNew();
    ASSERT_TRUE(pk != NULL);

    DapsSK* sk = NULL;

    uint32_t n = NUM_ADDRESSES;

    ErrorCodes error;
    ASSERT_EQ(error = dapsKeyGen(sk, pk, n), SK_NULL) << getErrorString(error);

    EXPECT_TRUE(pk != NULL);
    EXPECT_TRUE(sk == NULL);

    dapsPkFree(&pk);
}

TEST(key_gen_check, test_n_zero)
{
    DapsPK* pk = dapsPkNew();
    ASSERT_TRUE(pk != NULL);

    DapsSK* sk = dapsSkNew();
    ASSERT_TRUE(sk != NULL);

    uint32_t n = 0;

    ErrorCodes error;
    ASSERT_EQ(error = dapsKeyGen(sk, pk, n), KEY_GEN_N_ZERO) << getErrorString(error);

    ASSERT_TRUE(pk != NULL);
    ASSERT_TRUE(sk != NULL);

    dapsPkFree(&pk);
    dapsSkFree(&sk);
}

TEST(key_gen_check, test_sign_key_pair)
{
    DapsPK* pk = dapsPkNew();
    ASSERT_TRUE(pk != NULL);

    DapsSK* sk = dapsSkNew();
    ASSERT_TRUE(sk != NULL);

    uint32_t n = NUM_ADDRESSES;

    ErrorCodes error = dapsKeyGen(sk, pk, n);
    if(error != SUCCESS)
        fprintf(stderr, "%s\n", getErrorString(error));

    ASSERT_TRUE(pk != NULL);
    ASSERT_TRUE(pk->pk_sign_ != NULL);

    ASSERT_TRUE(sk != NULL);
    ASSERT_TRUE(sk->sk_sign_ != NULL);

    const EC_POINT* pk_sign;
    const EC_GROUP* pk_grp_sign;
    pk_sign = EC_KEY_get0_public_key(pk->pk_sign_);
    pk_grp_sign = EC_KEY_get0_group(pk->pk_sign_);

    const BIGNUM* sk_sign;
    const EC_GROUP* sk_grp_sign;
    sk_sign = EC_KEY_get0_private_key(sk->sk_sign_);
    sk_grp_sign = EC_KEY_get0_group(sk->sk_sign_);

    EC_POINT* res = EC_POINT_new(sk_grp_sign);

    EC_POINT_mul(sk_grp_sign, res, sk_sign, NULL, NULL, NULL);

    EXPECT_EQ(EC_POINT_cmp(pk_grp_sign, res, pk_sign, NULL), 0);

    EC_POINT_free(res);

    dapsPkFree(&pk);
    dapsSkFree(&sk);
}

TEST(key_gen_check, test_el_gamal_enc)
{
    DapsPK* pk = dapsPkNew();
    ASSERT_TRUE(pk != NULL);

    DapsSK* sk = dapsSkNew();
    ASSERT_TRUE(sk != NULL);

    uint32_t n = NUM_ADDRESSES;

    ErrorCodes error = dapsKeyGen(sk, pk, n);
    if(error != SUCCESS)
        fprintf(stderr, "%s\n", getErrorString(error));

    ASSERT_TRUE(sk != NULL);
    ASSERT_TRUE(sk->r_i_ != NULL);
    ASSERT_TRUE(sk->rho_i_ != NULL);

    ASSERT_TRUE(pk != NULL);
    ASSERT_TRUE(pk->c1_i_ != NULL);
    ASSERT_TRUE(pk->c2_i_ != NULL);

    const EC_POINT* pk_enc;
    pk_enc = EC_KEY_get0_public_key(pk->pk_enc_);

    const EC_GROUP* group;
    group = EC_KEY_get0_group(sk->sk_sign_);

    EC_POINT* res = EC_POINT_new(group);

    for(int i = 0; i < sk->n_; ++i)
    {
        EC_POINT_mul(group, res, sk->r_i_[i], NULL, NULL, NULL);
        EXPECT_EQ(EC_POINT_cmp(group, res, pk->c1_i_[i], NULL), 0);

        EC_POINT_mul(group, res, sk->rho_i_[i], pk_enc, sk->r_i_[i], NULL);
        EXPECT_EQ(EC_POINT_cmp(group, res, pk->c2_i_[i], NULL), 0);
    }

    EC_POINT_free(res);

    dapsPkFree(&pk);
    dapsSkFree(&sk);
}

TEST(key_gen_check, test_randomness_enc)
{
    DapsPK* pk = dapsPkNew();
    ASSERT_TRUE(pk != NULL);

    DapsSK* sk = dapsSkNew();
    ASSERT_TRUE(sk != NULL);

    uint32_t n = NUM_ADDRESSES;

    ErrorCodes error = dapsKeyGen(sk, pk, n);
    if(error != SUCCESS)
        fprintf(stderr, "%s\n", getErrorString(error));

    ASSERT_TRUE(sk != NULL);
    ASSERT_TRUE(sk->sk_sign_ != NULL);

    ASSERT_TRUE(pk != NULL);
    ASSERT_TRUE(pk->y_ != NULL);

    const EC_GROUP* group;
    group = EC_KEY_get0_group(sk->sk_sign_);

    const BIGNUM* sk_sign;
    sk_sign = EC_KEY_get0_private_key(sk->sk_sign_);

    //convert secret signing key to char array
    uint8_t* sk_sign_char;
    size_t sk_sign_length;
    int size;
    size = BN_num_bytes(sk_sign);
    sk_sign_length = (size_t)size;
    sk_sign_char = (uint8_t*)OPENSSL_malloc(sk_sign_length);
    BN_bn2bin(sk_sign, sk_sign_char);

    //set up hkdf
    EVP_PKEY_CTX* pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, HKDF_SALT, strlen(HKDF_SALT));
    EVP_PKEY_CTX_add1_hkdf_info(pctx, HKDF_INFO, strlen(HKDF_INFO));
    EVP_PKEY_CTX_set1_hkdf_key(pctx, sk_sign_char, sk_sign_length);

    int bn_max_length;
    size_t bn_max_length_unsigned;
    bn_max_length = BN_num_bytes(EC_GROUP_get0_order(group));
    bn_max_length_unsigned = (size_t)bn_max_length;

    //get y
    uint8_t* tmp;
    tmp = (uint8_t*)OPENSSL_malloc(bn_max_length_unsigned);

    BIGNUM* tmp_bn = BN_new();

    for(int i = 0; i < pk->n_; ++i)
    {
        //get r_i
        EVP_PKEY_derive(pctx, tmp, &bn_max_length_unsigned);
        for(int j = 0; j < bn_max_length_unsigned; ++j)
            tmp[j] ^= pk->y_[i][j];

        //convert to BIGNUM
        BN_bin2bn(tmp, bn_max_length, tmp_bn);
        EXPECT_TRUE(BN_cmp(tmp_bn, sk->r_i_[i]) == 0);

        //get rho_i
        EVP_PKEY_derive(pctx, tmp, &bn_max_length_unsigned);
        for(int j = 0; j < bn_max_length_unsigned; ++j)
            tmp[j] ^= pk->y_[i + pk->n_][j];

        //convert to BIGNUM
        BN_bin2bn(tmp, bn_max_length, tmp_bn);
        EXPECT_TRUE(BN_cmp(tmp_bn, sk->rho_i_[i]) == 0);
    }

    BN_free(tmp_bn);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(sk_sign_char);
    OPENSSL_free(tmp);

    dapsPkFree(&pk);
    dapsSkFree(&sk);
}