//----------------------------------------------------------------------------------------------------------------------
// Code adapted from:
//
// Title: Libbitcoin: Interactive HD Keychain
// Author: Aaron Jaramillo
// Date: 2017
// Availability: http://aaronjaramillo.org/libbitcoin-interactive-hd-keychain
//----------------------------------------------------------------------------------------------------------------------

#ifndef BITCOIN_APP_HD_WALLET_TESTNET_H
#define BITCOIN_APP_HD_WALLET_TESTNET_H

#include <bitcoin/bitcoin.hpp>
#include <iostream>

using namespace bc;

class HDWalletTestnet
{
private:
    data_chunk entropy_;
    data_chunk seed_;
    wallet::word_list mnemonic_;
    wallet::hd_private private_key_;
    wallet::hd_public public_key_;

public:
    HDWalletTestnet();

    explicit HDWalletTestnet(wallet::word_list mnemonic_seed);

    //getter
    const wallet::hd_private childPrivateKey(uint32_t index) const;
    const wallet::hd_public childPublicKey(uint32_t index) const;
    const wallet::payment_address childAddress(uint32_t index) const;

    //------------------------------------------------------------------------------------------------------------------
    // Broadcasts a transaction to the Bitcoin (test-)network
    // @input:
    //   tx...transaction to broadcast
    //------------------------------------------------------------------------------------------------------------------
    void broadcastTransaction(chain::transaction& tx) const;

    //display functions
    void displayPrivateKey() const;
    void displayChildPrivateKey(uint32_t index) const;
    void displayAddress(uint32_t index) const;
    void addressRange(uint32_t start, uint32_t end) const;
    void displayMnemonic() const;
    void dumpKeys() const;
};


#endif //BITCOIN_APP_HD_WALLET_TESTNET_H
