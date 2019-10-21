
> ![](warning.jpg)  
> # Project is not yet production ready.
...

SharpHash [![License](http://img.shields.io/badge/license-MPL2-blue.svg)](https://github.com/Ron4fun/HashLib4CSharp/blob/master/LICENSE) [![Build Status](https://travis-ci.org/Ron4fun/SharpHash.svg?branch=master)](https://travis-ci.org/Ron4fun/SharpHash)
====

SharpHash is a C# hashing library that provides a fluent interface for computing hashes and checksums of strings, files, streams, bytearrays and untyped data to mention but a few.

It also supports **Incremental Hashing**, **Cloning** and **NullDigest**.

Available Algorithms
----------------------------------------

 ### Hashes
----------------------------------------
##### Cyclic Redundancy Checks

* `All CRC Variants from CRC3 to CRC64` 

##### Checksums

* `Adler32`

##### Non-Cryptographic Hash Functions 
----------------------------------------

###### 32 bit hashes

* `AP` `BKDR` `Bernstein` `Bernstein1` `DEK` `DJB` `ELF` `FNV` 

* `FNV1a` `JS` `Jenkins3` `Murmur2` `MurmurHash3_x86_32` `OneAtTime`

*  `PJW` `RS` `Rotating` `SDBM` `ShiftAndXor` `SuperFast` `XXHash32`

###### 64 bit hashes

* `FNV64` `FNV1a64` `Murmur2_64` `SipHash2_4` `XXHash64`

###### 128 bit hashes

* `MurmurHash3_x86_128` `MurmurHash3_x64_128` 

##### Cryptographic Hash Functions 
----------------------------------------

 * `MD2`

 * `MD4`

 * `MD5`

 * `SHA-0`

 * `SHA-1`

 * `SHA-2 (224, 256, 384, 512, 512-224, 512-256)`

 * `GOST 34.11-94`

 * `GOST R 34.11-2012 (AKA Streebog) (256, 512)`
 
 * `Grindahl (256, 512)`
 
 * `HAS160`

 * `RIPEMD (128, 256, 256, 320)`

 * `Tiger (128, 160, 192 (Rounds 3, 4, 5))` 

 * `Tiger2 (128, 160, 192 (Rounds 3, 4, 5))` 
 
 * `Snefru (128, 256)`
 
 * `Haval (128, 160, 192, 224, 256 (Rounds 3, 4, 5))`
 
 * `Panama`
 
 * `RadioGatun (RadioGatun32, RadioGatun64)`

 * `WhirlPool`

 * `Blake2B (160, 256, 384, 512)`
 
 * `Blake2S (128, 160, 224, 256)`

 * `SHA-3 (224, 256, 384, 512)`
 
 * `Keccak (224, 256, 288, 384, 512)`

### Key Derivation Functions
----------------------------------------

###### Password Hashing Schemes (Password Based Key Derivation Functions)

----------------------------------------

* `PBKDF2`
 
* `Argon2 (2i, 2d and 2id variants)`

* `Scrypt`

### MAC
----------------------------------------

* `HMAC (all supported hashes)`

* `KMAC (KMAC128, KMAC256)`

### XOF (Extendable Output Function)
----------------------------------------

* `Shake (Shake-128, Shake-256)`

* `CShake (CShake-128, CShake-256)`

* `Blake2X (Blake2XS, Blake2XB)`

* `KMACXOF (KMAC128XOF, KMAC256XOF)`


### Other Implementations
----------------------------------------

If you want implementations in other languages, you can check out these

* [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal) by Ugochukwu Mmaduekwe
* [HashLib4CPP](https://github.com/ron4fun/HashLib4CPP) by Mbadiwe Nnaemeka Ronald
* [HashLib4Python](https://github.com/ron4fun/HashLib4Python) by Mbadiwe Nnaemeka Ronald

### Tip Jar
----------------------------------------

* :dollar: **Bitcoin**: `1Mcci95WffSJnV6PsYG7KD1af1gDfUvLe6`