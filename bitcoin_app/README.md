# bitcoin_app

Implementation of an application for Bitcoin in C++ using the libbitcoin library and a double-authentication-preventing signature (DAPS) scheme.

This application simulates an ATM-like provider that enables a client to pay offline with Bitcoin at several, independent points of sale. Therefore the client creates at first a deposit with an pay to script hash contract. The provider checks, if the deposit transaction is in the blockchain and if the transaction is valid. If so, the provider gives the client a signed initial state. The state contains informations like the maximum amount of Bitcoin the client can spent, the amount of Bitcoin he has spent, how long the Deposit is locked, a revision number and so on.

Now the client can make payments to a point of sale, by sending the state and a transaction, which is signed with a DAPS. Then the point of sale will check the state, the signature of the state, the transaction and the signature of the transaction. If everything is valid a signed and updated version of the state is send back to the client. This updated state is now signed with the private key of the point of sale and additionally contains the corresponding public key, which was signed by the provider.

Before the locktime of the client's deposit expires, the provider collects all transactions from the points of sale, checks for double-spending and claims the Bitcoin from the deposit. If the client has double-spend, the provider can extract the client's private key from the transactions and transfer all Bitcoin in the deposit to an address under his control.

## Dependencies
+ DAPS
+ libbitcoin v3
+ libbitcoin-client v3
+ libbitcoin-protocol v3

## Usage
When the program is started a hierarchical deterministic Bitcoin testnet wallet is created for the client and the provider. The seed for the wallet generation is derived from a mnemonic seed, to get the same keys and addresses each time. When the wallets are generated, the mnemonic seed as well as the testnet address is displayed.
```
New Provider:
Mnemonic:
equip address calm seed priority garden fade thing axis used couch abuse
Address: miv8cV8pwU9CagsW7yMpqvHcUeh47YTM4W

New Client (id = 0):
Mnemonic:
shop convince absorb invite black myself harsh mother skin subject supply prefer
Address: mpZfrRvDxSct69T77AgkRAF4LeJqQ5nyQ6
```
After this setup the balance of the clients address is queried from the testnet, to let the user know how much Bitcoins are available in the wallet. Then options to set up a deposit are shown as follows.
```
Please choose an option:
1) create a deposit only
2) create a deposit and make payments
3) make payments with an existing deposit
4) exit
```

### Creating a deposit
When option 1) or 2) is chosen a new deposit will be created. Therefore the hash of a transaction with an unspent transaction output (utxo) as well as the index of this output (starting at 0) has to be entered.
```
please enter the hash of a transaction with an unspend transaction output (utxo) to create the deposit:
3fbd3cd611f42869513cde41ee66fe378871017616f9625ee8cf7aad0a7b9aae
please enter the output index of the utxo: 1
```
Thereafter the Satoshi, that should be placed in the deposit, and the number of days the deposit should be locked can be specified. Finally the time until the deposit is locked is displayed in unix time and the deposit is created.

__Caution!__  
_When creating a new deposit it is important to write down the displayed locking time, because the time will not be saved by the application and is needed to restore the locking script once the application has exited. Without the locking script it is not possible to spent the Bitcoin in the deposit._

To use an existing deposit (option 3) the transaction hash of the deposit, the locking time and the Satoshi in the deposit must be provided.

### Making payments
Once a deposit is successfully created or restored, the provider will verify the deposit in the Bitcoin network. As confirming a transaction in Bitcoin might take 10-20 minutes, the validation of the deposit may fail at the first attempt and has to be repeated. After the verification, the client receives a signed state and the following options are displayed.
```
Please choose an option:
1) make transactions
2) double spent
3) close deposit
4) reclaim deposit
5) exit
```
With option 1) the client can make payments to a point of sale of his choice. When choosing option 2) at first a normal transaction is performed and then the next time either option 1) or 2) is chosen a double-spending transaction is send to a point of sale. After the client made the last transaction the deposit can be closed with option 3). This is usually initialized by the provider, but to keep this example program simple it is initialized by the client (user). Either way, the provider will now collect all transactions from the points of sale and transfer the Bitcoin from the deposit to an address under his control. In a real world scenario the points of sale would additionally receive payments from the provider, according to the transactions they transmitted to the provider. If for any reason the provider does not return an initial state or the points of sale do not accept the transactions from the client, the client can reclaim his deposit after the deposit has expired with option 4).
