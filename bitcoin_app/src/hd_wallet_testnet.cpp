//----------------------------------------------------------------------------------------------------------------------
// Code adapted from:
//
// Title: Libbitcoin: Interactive HD Keychain
// Author: Aaron Jaramillo
// Date: 2017
// Availability: http://aaronjaramillo.org/libbitcoin-interactive-hd-keychain
//----------------------------------------------------------------------------------------------------------------------

#include <bitcoin/client.hpp>
#include "defines.h"
#include "hd_wallet_testnet.h"

HDWalletTestnet::HDWalletTestnet()
{
    entropy_ = data_chunk(16);
    pseudo_random_fill(entropy_);
    mnemonic_ = wallet::create_mnemonic(entropy_);
    seed_ = to_chunk(wallet::decode_mnemonic(mnemonic_));
    private_key_ = wallet::hd_private(seed_, wallet::hd_private::testnet);
    public_key_ = private_key_.to_public();
}

HDWalletTestnet::HDWalletTestnet(const wallet::word_list mnemonic_seed)
{
    seed_ = to_chunk(wallet::decode_mnemonic(mnemonic_seed));
    mnemonic_ = mnemonic_seed;
    private_key_ = wallet::hd_private(seed_, wallet::hd_private::testnet);
    public_key_ = private_key_.to_public();
}

const wallet::hd_private HDWalletTestnet::childPrivateKey(uint32_t index) const
{
    return private_key_.derive_private(index);
}

const wallet::hd_public HDWalletTestnet::childPublicKey(uint32_t index) const
{
    return public_key_.derive_public(index);
}

const wallet::payment_address HDWalletTestnet::childAddress(uint32_t index) const
{
    return wallet::payment_address(wallet::ec_public(childPublicKey(index).point()), 0x6f);
}

void HDWalletTestnet::broadcastTransaction(chain::transaction& tx) const
{
    client::connection_type connection = {};
    connection.retries = 3;
    connection.timeout_seconds = 8;
    connection.server = config::endpoint(LIBBITCOIN_TESTNET_SERVER);

    client::obelisk_client client(connection);

    if(!client.connect(connection))
    {
        std::cout << "Fail" << std::endl;
    }
    else
    {
        if(VERBOSE && NETWORK_IO_VERBOSE)
            std::cout << "Connection Succeeded" << std::endl;
    }

    static const auto on_done = [](const code& ec) {
        std::cout << "transaction broadcast: " << ec.message() << std::endl;
    };

    static const auto on_error = [](const code& ec) {
        std::cout << "Error Code: " << ec.message() << std::endl;
    };

    client.transaction_pool_broadcast(on_error, on_done, tx);
    client.wait();
}

//display functions
void HDWalletTestnet::displayPrivateKey() const
{
    std::cout << "Private Key: " << private_key_.encoded() << std::endl;
}

void HDWalletTestnet::displayChildPrivateKey(uint32_t index) const
{
    std::cout << "Child Key: " << childPrivateKey(index).encoded() << std::endl;
}

void HDWalletTestnet::displayAddress(uint32_t index) const
{
    std::cout << "Address: " << childAddress(index).encoded() << std::endl;
}

void HDWalletTestnet::addressRange(uint32_t start, uint32_t end) const
{
    while(start != end)
    {
        displayAddress(start);
        start++;
    }
}

void HDWalletTestnet::displayMnemonic() const
{
    if(wallet::validate_mnemonic(mnemonic_))
    {
        std::string mnemonic_string = join(mnemonic_);
        std::cout << mnemonic_string << std::endl;
    }
    else
    {
        std::cout << "mnemonic invalid!" << std::endl;
    }
}

void HDWalletTestnet::dumpKeys() const
{
    displayMnemonic();
    displayPrivateKey();
    displayChildPrivateKey(1);
    displayAddress(1);
}