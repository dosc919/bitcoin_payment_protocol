//
// Created by dominik on 11.01.18.
//

#include "transactiondata.h"

TransactionData::TransactionData(bc::chain::transaction tx, uint32_t rev_nr, std::array<uint8_t, RND_NR_SIZE_BYTES>& rand_nr) :
        tx_(std::move(tx)), revision_nr_(rev_nr), random_nr_(rand_nr)
{
}

TransactionData::~TransactionData() = default;

const uint64_t TransactionData::getAmountSpent() const
{
    return tx_.outputs()[0].value();
}

const bc::hash_digest TransactionData::getTransactionHash() const
{
    return tx_.inputs()[0].previous_output().hash();
}

const bc::wallet::payment_address TransactionData::getOutputAddress() const
{
    return tx_.outputs()[0].address(bc::wallet::payment_address::testnet_p2kh);
}

const bc::chain::transaction TransactionData::getTransaction() const
{
    return tx_;
}

const uint32_t TransactionData::getRevisionNumber() const
{
    return revision_nr_;
}

const std::array<uint8_t, RND_NR_SIZE_BYTES> TransactionData::getRandomNumber() const
{
    return random_nr_;
}

const std::vector<uint8_t> TransactionData::getBytes() const
{
    std::vector<uint8_t> bytes = std::vector<uint8_t>(sizeof(revision_nr_));
    memcpy(&(bytes[0]), &revision_nr_, sizeof(revision_nr_));
    bytes.insert(bytes.end(), random_nr_.begin(), random_nr_.end());

    std::vector<uint8_t> bc_transaction_bytes = tx_.to_data();
    bytes.insert(bytes.end(), bc_transaction_bytes.begin(), bc_transaction_bytes.end());

    return bytes;
}