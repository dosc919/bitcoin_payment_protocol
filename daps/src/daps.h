//
// Created by dominik on 27.09.17.
//

#ifndef DAPS_DAPS_H
#define DAPS_DAPS_H

#include <openssl/evp.h>
#include "data_structures.h"
#include "const_and_error.h"


//main functions
ErrorCodes dapsKeyGen(DapsSK* sk, DapsPK* pk, uint32_t n);

ErrorCodes dapsKeyGenECDSAExternal(DapsSK* sk, DapsPK* pk, uint32_t n, const uint8_t* sk_ecdsa);

ErrorCodes dapsSign(DapsSignature* sign, DapsSK* sk, DapsPK* pk, DapsMessage* m);

ErrorCodes dapsVerify(DapsPK* pk, DapsMessage* m, DapsSignature* sign);

ErrorCodes dapsExtr(DapsSK* sk, DapsPK* pk, DapsMessage* m1, DapsMessage* m2, DapsSignature* sign1, DapsSignature* sign2);

//helper functions
void dapsPkFree(DapsPK** pk);
void dapsSkFree(DapsSK** sk);
void dapsMsgFree(DapsMessage** m);
void dapsSignatureFree(DapsSignature** sign);

DapsPK* dapsPkNew();
DapsSK* dapsSkNew();
DapsMessage* dapsMsgNew(uint32_t i, const uint8_t* p, size_t p_length);
DapsSignature* dapsSignatureNew(DapsPK* pk);

#endif //DAPS_DAPS_H
