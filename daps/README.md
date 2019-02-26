# daps

Implementation of a double-authentication-preventing signature scheme (DAPS) in C using the OpenSSL library.

## Dependencies
+ OpenSSL (1.1.0g was tested)

## Usage

### Memory Management
The following functions create a new public key (DapsPK), secret key (DapsSK), message (DapsMessage) and signature (DapsSignature) struct respectively, which are needed in the rest of the framework. When an error occurs during allocation, a null pointer is returned.
```c
DapsPK* dapsPkNew();
DapsSK* dapsSkNew();
DapsMessage* dapsMsgNew(uint32_t i, const uint8_t* p, size_t p_length);
DapsSignature* dapsSignatureNew(DapsPK* pk);
```
In the dapsMsgNew function the __i__ parameter specifies the index (or address) for which the signature is created. __p__ is a byte-array containing the message and __p_length__ is the length of that array.  
The dapsSignatureNew function takes a DapsPK as an input parameter, to create a signature object with the same elliptic curve group as the public key.

The free-functions deallocate the memory and set the struct to a null pointer. This makes it possible to check if the struct is still valid and prevents double free.
```c
void dapsPkFree(DapsPK** pk);
void dapsSkFree(DapsSK** sk);
void dapsMsgFree(DapsMessage** m);
void dapsSignatureFree(DapsSignature** sign);
```

### Creating a Key Pair
The dapsKeyGen function generates a new secret key - public key pair and returns them in the __sk__ and __pk__ parameter. __sk__ and __pk__ should be allocated with the dapsPkNew and dapsSkNew functions beforehand. The __n__ parameter specifies the number of addresses that can be signed with the secret key. When an error occurs, an error code enum is returned as explained in the section "Errors".
```c
ErrorCodes dapsKeyGen(DapsSK* sk, DapsPK* pk, uint32_t n);
```

The dapsKeyGenECDSAExternal takes additionally a byte-array, which contains an existing ECDSA secret key, as input. The key has to have a size of exactly 32 bytes. The DAPS key pair will be generated with this key using the secp256k1 curve and the same parameters as used in Bitcoin.
```c
ErrorCodes dapsKeyGenECDSAExternal(DapsSK* sk, DapsPK* pk, uint32_t n, const uint8_t* sk_ecdsa);
```

### Signing and Verifying
dapsSign takes a secret key __sk__, a public key __pk__ and a message __m__ as input and returns a signature __sign__. The public key is needed for signing, because __sk__ does not contain the ElGamal key, which is necessary for the zero-knowledge proof. dapsVerify takes a public key __pk__, a message __m__ and a signature __sign__ as input and returns an enum, which states if the verification was successful. If an error occurred during execution, both functions return an error code. More details on the error code can be found in the section "Errors". All structs should be allocated with the corresponding new functions before calling dapsSign and dapsVerify.
```c
ErrorCodes dapsSign(DapsSignature* sign, DapsSK* sk, DapsPK* pk, DapsMessage* m);
ErrorCodes dapsVerify(DapsPK* pk, DapsMessage* m, DapsSignature* sign);
```

### Extraction
The extraction function takes a public key __pk__, two messages __m1__ and __m2__, two signatures __sign1__ and __sign2__ and, if the extraction was successful, returns a secret key __sk__. The messages have to be colliding, therefore the address of __m1__ has to be the same as the address of __m2__ and the payload of the messages has to be different. __sign1__ has to be a valid signature for __m1__ and __sign2__ a valid signature for __m2__. When an error occurred during the extraction an error code is returned as detailed in the "Errors" section. All structs should be allocated with the corresponding function beforehand.
```c
ErrorCodes dapsExtr(DapsSK* sk, DapsPK* pk, DapsMessage* m1, DapsMessage* m2, DapsSignature* sign1, DapsSignature* sign2);
```

### Errors

When an error occurs during the execution of a function an error code enum is returned. This enum can be found in the "const_and_error.h" file. With the getErrorString function a printable string can be obtained from the error code.

```c
const char* getErrorString(ErrorCodes error);
```
