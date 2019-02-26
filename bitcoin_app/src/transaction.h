//
// Created by dominik on 14.01.18.
//

#ifndef BITCOIN_APP_TRANSACTION_H
#define BITCOIN_APP_TRANSACTION_H


#include <bitcoin/bitcoin.hpp>
#include "transactiondata.h"
#include "defines.h"

class Transaction;
typedef std::shared_ptr<Transaction> TransactionPtr;
typedef std::shared_ptr<const Transaction> ConstTransactionPtr;

class Transaction
{
private:
    TransactionData data_;
    ConstDapsSigPtr sign_;

public:
    Transaction(bc::chain::transaction& tx, uint32_t rev_nr, std::array<uint8_t, RND_NR_SIZE_BYTES> rand_nr);
    ~Transaction();

    //getter
    const TransactionData getData() const;
    ConstDapsSigPtr getSignature() const;

    //setter
    void setSignature(ConstDapsSigPtr transaction_signature);

    //------------------------------------------------------------------------------------------------------------------
    // prints the content of data_ to stdout
    //------------------------------------------------------------------------------------------------------------------
    void display();
};


#endif //BITCOIN_APP_TRANSACTION_H
