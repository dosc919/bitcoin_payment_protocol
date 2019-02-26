
find_package(PkgConfig)
find_package(Boost)
find_library(LIB_BITCOIN libbitcoin libbitcoin-client libbitcoin-protocol)

pkg_check_modules(LIBBITCOIN_LDFLAGS libbitcoin)

add_subdirectory(../../daps/src daps)

INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
ADD_DEFINITIONS("-DHAS_BOOST")

add_executable(bitcoin_app main.cpp provider.cpp provider.h client.cpp client.h point_of_sale.cpp point_of_sale.h statedata.cpp statedata.h transactiondata.cpp transactiondata.h state.cpp state.h transaction.cpp transaction.h defines.h hd_wallet_testnet.cpp hd_wallet_testnet.h)

add_compile_options(LIBBITCOIN_LDFLAGS)

target_link_libraries(bitcoin_app daps boost_system bitcoin bitcoin-client bitcoin-protocol)
