# Multisig example
A simple example on how to use multisig with P2SH, pay to script hash

# Libs needed to run this
- [bitcoinj]: google bitcoin library
- [guava]: google core libraries

## Important notes

This code is only educational. The purpose is to understand how to build and spend multisig transactions. If you want to use this code for a project, feel free do to so, but keep in mind there is much more needed for production use. If you run the code as it is, it will build and sign a transaction with one input and the default output is 0.1 mBTC or 100 bits. The input you use should have 0.2 mBTC or 200 bits on it. Leaving 0.1 mBTC as mining fee. The whole input gets spended, so if you are not careful you will end up with a huge mining fee.

[bitcoinj]:https://github.com/bitcoinj/bitcoinj
[guava]:https://github.com/google/guava
