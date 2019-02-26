//
// Created by dominik on 17.10.17.
//

#include "gtest/gtest.h"

extern "C"
{
#include "data_structures.h"
#include "const_and_error.h"
#include "daps.h"
}

#define NUM_ADDRESSES (10)
#define ADDRESS_TO_SIGN (5)

static const uint8_t P_TEST1[] = {0x30, 0x46, 0x2, 0x21, 0x0, 0xbf, 0xbe, 0x66, 0xe6, 0x81, 0xd3, 0xaf, 0x5d, 0x1e,
                                  0x23, 0x26, 0x44, 0x1a, 0x9, 0x3a, 0x5e, 0x40, 0xb4, 0x58, 0x2d, 0x3f, 0xd4, 0xe6,
                                  0xc3, 0x0,  0x79, 0x6d, 0x8e, 0xb8, 0xab, 0xdc, 0x49};
static const uint8_t P_TEST2[] = {0x50, 0x66, 0x25, 0x29, 0x50, 0x1f, 0x4e, 0x6a, 0x56, 0x81, 0xf3, 0xaf, 0x5d, 0x1e,
                                  0x23, 0x26, 0x44, 0x1e, 0x9, 0x3a, 0x5e, 0x40, 0xb4, 0x58, 0x22, 0x3f, 0xd4, 0xe6,
                                  0xc3, 0x0,  0x79, 0x6d, 0x89, 0xb4, 0xb, 0x4c, 0x4b};

class ExtractionTest : public ::testing::Test
{
protected:
    virtual void SetUp()
    {
        pk_ = dapsPkNew();
        sk_ = dapsSkNew();

        ASSERT_TRUE(pk_ != NULL);
        ASSERT_TRUE(sk_ != NULL);

        n_ = NUM_ADDRESSES;

        ASSERT_EQ(error_ = dapsKeyGen(sk_, pk_, n_), SUCCESS) << getErrorString(error_);

        sign_ = dapsSignatureNew(pk_);
        sign2_ = dapsSignatureNew(pk_);
        ASSERT_TRUE(sign_ != NULL);
        ASSERT_TRUE(sign2_ != NULL);
    }

    virtual void TearDown()
    {
        dapsSkFree(&sk_);
        dapsPkFree(&pk_);
        dapsMsgFree(&msg_);
        dapsSignatureFree(&sign_);
        dapsSignatureFree(&sign2_);
    }

    DapsPK* pk_;
    DapsSK* sk_;
    DapsSignature* sign_;
    DapsSignature* sign2_;
    DapsMessage* msg_;
    ErrorCodes error_;
    uint32_t n_;
};


TEST_F(ExtractionTest, test_extraction)
{
    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST1, sizeof(P_TEST1));
    ASSERT_LT(msg_->i_, n_);
    assert(msg_->p_ != NULL);

    DapsMessage* msg_2 = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST2, sizeof(P_TEST2));
    ASSERT_LT(msg_2->i_, n_);
    assert(msg_2->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    ASSERT_EQ(error_ = dapsSign(sign2_, sk_, pk_, msg_2), SUCCESS) << getErrorString(error_);

    DapsSK* sk_extr = dapsSkNew();
    ASSERT_EQ(error_ = dapsExtr(sk_extr, pk_, msg_, msg_2, sign_, sign2_), SUCCESS) << getErrorString(error_);

    const BIGNUM* sk_bn;
    const BIGNUM* sk_extr_bn;

    sk_bn = EC_KEY_get0_private_key(sk_->sk_sign_);
    sk_extr_bn = EC_KEY_get0_private_key(sk_extr->sk_sign_);

    EXPECT_TRUE(BN_cmp(sk_bn, sk_extr_bn) == 0);

    EXPECT_TRUE(sk_->n_ == sk_extr->n_);

    ASSERT_TRUE(sk_extr->r_i_ != NULL);
    for(int i = 0; i < sk_extr->n_; ++i)
    {
        ASSERT_TRUE(sk_extr->r_i_[i] != NULL);
        EXPECT_TRUE(BN_cmp(sk_->r_i_[i], sk_extr->r_i_[i]) == 0);
    }

    ASSERT_TRUE(sk_extr->rho_i_ != NULL);
    for(int i = 0; i < sk_extr->n_; ++i)
    {
        ASSERT_TRUE(sk_extr->rho_i_[i] != NULL);
        EXPECT_TRUE(BN_cmp(sk_->rho_i_[i], sk_extr->rho_i_[i]) == 0);
    }

    dapsSkFree(&sk_extr);
    dapsMsgFree(&msg_2);
}

TEST_F(ExtractionTest, test_extraction_different_address)
{
    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST1, sizeof(P_TEST1));
    ASSERT_LT(msg_->i_, n_);
    assert(msg_->p_ != NULL);

    DapsMessage* msg_2 = dapsMsgNew(ADDRESS_TO_SIGN + 1, P_TEST2, sizeof(P_TEST2));
    ASSERT_LT(msg_2->i_, n_);
    assert(msg_2->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    ASSERT_EQ(error_ = dapsSign(sign2_, sk_, pk_, msg_2), SUCCESS) << getErrorString(error_);

    DapsSK* sk_extr = dapsSkNew();
    ASSERT_EQ(error_ = dapsExtr(sk_extr, pk_, msg_, msg_2, sign_, sign2_), EXTRACT_ADDRESS_MISMATCH)
                                                                                              << getErrorString(error_);

    dapsSkFree(&sk_extr);
    dapsMsgFree(&msg_2);
}

TEST_F(ExtractionTest, test_extraction_same_payload)
{
    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST1, sizeof(P_TEST1));
    ASSERT_LT(msg_->i_, n_);
    assert(msg_->p_ != NULL);

    DapsMessage* msg_2 = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST1, sizeof(P_TEST1));
    ASSERT_LT(msg_2->i_, n_);
    assert(msg_2->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    ASSERT_EQ(error_ = dapsSign(sign2_, sk_, pk_, msg_2), SUCCESS) << getErrorString(error_);

    DapsSK* sk_extr = dapsSkNew();
    ASSERT_EQ(error_ = dapsExtr(sk_extr, pk_, msg_, msg_2, sign_, sign2_), EXTRACT_PAYLOAD_MATCH)
                                                                                              << getErrorString(error_);

    dapsSkFree(&sk_extr);
    dapsMsgFree(&msg_2);
}

TEST_F(ExtractionTest, test_extraction_signature_faulty)
{
    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST1, sizeof(P_TEST1));
    ASSERT_LT(msg_->i_, n_);
    assert(msg_->p_ != NULL);

    DapsMessage* msg_2 = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST2, sizeof(P_TEST2));
    ASSERT_LT(msg_2->i_, n_);
    assert(msg_2->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    ASSERT_EQ(error_ = dapsSign(sign2_, sk_, pk_, msg_2), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_enc_);
    BN_rand_range(sign_->s_, EC_GROUP_get0_order(group));

    DapsSK* sk_extr = dapsSkNew();
    ASSERT_EQ(error_ = dapsExtr(sk_extr, pk_, msg_, msg_2, sign_, sign2_), VERIFY_SIGNATURE_INVALID)
                                                                                              << getErrorString(error_);

    dapsSkFree(&sk_extr);
    dapsMsgFree(&msg_2);
}