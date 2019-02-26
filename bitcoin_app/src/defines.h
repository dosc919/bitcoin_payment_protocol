//
// Created by dominik on 18.01.18.
//

#ifndef BITCOIN_APP_DEFINES_H
#define BITCOIN_APP_DEFINES_H

extern "C"
{
#include "../../daps/src/daps.h"
};

//debug and output
#define VERBOSE true
#define PROVIDER_VERBOSE true
#define CLIENT_VERBOSE true
#define POINT_OF_SALE_VERBOSE true
#define NETWORK_IO_VERBOSE false

//Bitcoin related defines
#define LIBBITCOIN_TESTNET_SERVER "tcp://testnet.libbitcoin.net:19091"
#define TRANSACTION_FEE 10000
#define CURVE NID_secp256k1

//OpenSSL
struct DeleteEcKeyFunctor
{
    void operator()(EC_KEY* ec_key) { EC_KEY_free(ec_key); };
};
typedef std::unique_ptr<EC_KEY, DeleteEcKeyFunctor> EcKeyPtr;

typedef std::shared_ptr<EC_KEY> PubEcKeyPtr;
typedef std::shared_ptr<const EC_KEY> ConstPubEcKeyPtr;

typedef std::shared_ptr<const ECDSA_SIG> ConstEcdsaSigPtr;

//DAPS
struct DeleteDapsSkFunctor
{
    void operator()(DapsSK* daps_sk) { dapsSkFree(&daps_sk); };
};
typedef std::unique_ptr<DapsSK, DeleteDapsSkFunctor> DapsSkPtr;

typedef std::shared_ptr<DapsPK> DapsPkPtr;
typedef std::shared_ptr<const DapsPK> ConstDapsPkPtr;

typedef std::shared_ptr<DapsSignature> DapsSigPtr;
typedef std::shared_ptr<const DapsSignature> ConstDapsSigPtr;


#endif //BITCOIN_APP_DEFINES_H
