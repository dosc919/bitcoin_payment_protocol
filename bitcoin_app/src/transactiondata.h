//
// Created by dominik on 11.01.18.
//

#ifndef BITCOIN_APP_TRANSACTION_DATA_H
#define BITCOIN_APP_TRANSACTION_DATA_H


#include <bitcoin/bitcoin/chain/transaction.hpp>

#define RND_NR_SIZE_BYTES 32

class TransactionData
{
private:
    uint32_t revision_nr_;
    std::array<uint8_t, RND_NR_SIZE_BYTES> random_nr_;
    bc::chain::transaction tx_;

public:
    TransactionData(bc::chain::transaction tx, uint32_t rev_nr, std::array<uint8_t, RND_NR_SIZE_BYTES>& rand_nr);
    ~TransactionData();

    //getter
    const uint32_t getRevisionNumber() const;
    const std::array<uint8_t, RND_NR_SIZE_BYTES> getRandomNumber() const;
    const bc::chain::transaction getTransaction() const;
    const uint64_t getAmountSpent() const;
    const bc::hash_digest getTransactionHash() const;
    const bc::wallet::payment_address getOutputAddress() const;
    const std::vector<uint8_t> getBytes() const;
};


#endif //BITCOIN_APP_TRANSACTION_DATA_H
