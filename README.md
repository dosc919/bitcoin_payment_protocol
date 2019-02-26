
## Documentation

### Overview

This repository contains the implementation of a double-authentication-preventing signature (DAPS) scheme based on ECDSA and secret sharing and an application for these DAPS schemes in the Bitcoin setting. The code can be found in the corresponding daps and bitcoin_app folders.

The DAPS implementations are written in C using the OpenSSL library. Additionally, unit tests with the googletest framework have been implemented.

The application in Bitcoin is written in C++ and makes use of the DAPS implementation as well as the libbitcoin framework.

### Compilation and usage

The usage of the individual projects can be found in their subfolders to keep this file simple. The code can be compiled with the following commands:
+ cmake .
+ make

__Dependencies for daps:__
+ OpenSSL (1.1.0g was tested)

To run the tests for these two implementations the googletest repository [[1]](https://github.com/google/googletest) has to be cloned into the /test/lib/ folder of the corresponding project. After building the project the tests can be found in the /test/basic_tests subfolder in the build directory.

__Dependencies for bitcoin_app:__
+ DAPS
+ libbitcoin v3 [[2]](https://github.com/libbitcoin/libbitcoin)
+ libbitcoin-client v3 [[3]](https://github.com/libbitcoin/libbitcoin-client)
+ libbitcoin-protocol v3 [[4]](https://github.com/libbitcoin/libbitcoin-protocol)

libbitcoin is used for creating scripts and transactions in Bitcoin, libbitcoin-client for the communication with the Bitcoin (Testnet) network and libbitcoin-protocol is a dependency for
libbitcoin-client. It is important that all three libbitcoin libraries have version 3. An installation guide can be found on [[5]](http://aaronjaramillo.org/libbitcoin-v3-installing-libbitcoin-client).



[1] https://github.com/google/googletest (commit: 0510530 was tested)  
[2] https://github.com/libbitcoin/libbitcoin  
[3] https://github.com/libbitcoin/libbitcoin-client  
[4] https://github.com/libbitcoin/libbitcoin-protocol  
[5] http://aaronjaramillo.org/libbitcoin-v3-installing-libbitcoin-client
