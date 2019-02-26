//
// Created by dominik on 14.01.18.
//

#include "transaction.h"

Transaction::Transaction(bc::chain::transaction& tx, uint32_t rev_nr, std::array<uint8_t, RND_NR_SIZE_BYTES> rand_nr) :
        data_(tx, rev_nr, rand_nr)
{
}

Transaction::~Transaction() = default;

const TransactionData Transaction::getData() const
{
    return data_;
}

ConstDapsSigPtr Transaction::getSignature() const
{
    return sign_;
}

void Transaction::setSignature(ConstDapsSigPtr transaction_signature)
{
    sign_ = std::move(transaction_signature);
}

void Transaction::display()
{
    std::cout << "revision nr.: " << data_.getRevisionNumber() << std::endl;

    std::array<uint8_t, RND_NR_SIZE_BYTES> rnd_nr = data_.getRandomNumber();
    std::cout << "random nr.  : ";
    for(int i = 0; i < RND_NR_SIZE_BYTES; ++i)
        printf("%02x ", rnd_nr[i]);
    std::cout << std::endl;

    std::cout << "input transaction:" << std::endl;
    for(const bc::chain::input& in : data_.getTransaction().inputs())
        std::cout << bc::encode_hash(in.previous_output().hash()) << " index: " << in.previous_output().index() << std::endl;

    std::cout << "output adresses:" << std::endl;
    std::cout << data_.getTransaction().outputs()[0].address(bc::wallet::payment_address::testnet_p2kh) << " : "
              << data_.getTransaction().outputs()[0].value() << " Satoshis" << std::endl;

    std::cout << data_.getTransaction().outputs()[1].address(bc::wallet::payment_address::testnet_p2kh) << " : "
              << data_.getTransaction().outputs()[1].value() << " Satoshis" << std::endl;

    /*for(const bc::chain::output& out : data_.getTransaction().outputs()) //?causes locking error
    {
        std::cout << out.address(bc::wallet::payment_address::testnet_p2kh) << " : " << out.value() << " Satoshis" << std::endl;
    }*/
}