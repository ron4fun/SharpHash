SharpHash [![License](http://img.shields.io/badge/license-MPL2-blue.svg)](https://github.com/Ron4fun/HashLib4CSharp/blob/master/LICENSE) [![Build Status](https://travis-ci.org/Ron4fun/SharpHash.svg?branch=master)](https://travis-ci.org/Ron4fun/SharpHash) [![Nuget](https://img.shields.io/nuget/v/SharpHash)](https://www.nuget.org/packages/SharpHash/) [![Nuget](https://img.shields.io/nuget/dt/SharpHash)](https://www.nuget.org/packages/SharpHash/)
====

SharpHash is a C# hashing library that provides a fluent interface for computing hashes and checksums of strings, files, streams, bytearrays and untyped data to mention but a few.

It also supports **Incremental Hashing**, **Cloning**, **NullDigest** and **HashName Builder**.

Available Algorithms
----------------------------------------

 ### Hashes
----------------------------------------
##### Cyclic Redundancy Checks

* `All CRC Variants from CRC3 to CRC64` :heavy_check_mark:

##### Checksums

* `Adler32` :heavy_check_mark:

##### Non-Cryptographic Hash Functions 
----------------------------------------

###### 32 bit hashes

* `AP` `BKDR` `Bernstein` `Bernstein1` `DEK` `DJB` `ELF` `FNV` :heavy_check_mark:

* `FNV1a` `JS` `Jenkins3` `Murmur2` `MurmurHash3_x86_32` `OneAtTime` :heavy_check_mark:

*  `PJW` `RS` `Rotating` `SDBM` `ShiftAndXor` `SuperFast` `XXHash32` :heavy_check_mark:

###### 64 bit hashes

* `FNV64` `FNV1a64` `Murmur2_64` `SipHash64_2_4` `XXHash64` :heavy_check_mark:

###### 128 bit hashes

* `MurmurHash3_x86_128` `MurmurHash3_x64_128` `SipHash128_2_4` :heavy_check_mark:

##### Cryptographic Hash Functions 
----------------------------------------

 * `MD2` :heavy_check_mark:

 * `MD4` :heavy_check_mark:

 * `MD5` :heavy_check_mark:

 * `SHA-0` :heavy_check_mark:

 * `SHA-1` :heavy_check_mark:

 * `SHA-2 (224, 256, 384, 512, 512-224, 512-256)` :heavy_check_mark:

 * `GOST 34.11-94` :heavy_check_mark:

 * `GOST R 34.11-2012 (AKA Streebog) (256, 512)` :heavy_check_mark:
 
 * `Grindahl (256, 512)` :heavy_check_mark:
 
 * `HAS160` :heavy_check_mark:

 * `RIPEMD (128, 256, 256, 320)` :heavy_check_mark:

 * `Tiger (128, 160, 192 (Rounds 3, 4, 5))` :heavy_check_mark:

 * `Tiger2 (128, 160, 192 (Rounds 3, 4, 5))` :heavy_check_mark:
 
 * `Snefru (128, 256)` :heavy_check_mark:
 
 * `Haval (128, 160, 192, 224, 256 (Rounds 3, 4, 5))` :heavy_check_mark:
 
 * `Panama` :heavy_check_mark:
 
 * `RadioGatun (RadioGatun32, RadioGatun64)` :heavy_check_mark:

 * `WhirlPool` :heavy_check_mark:

 * `Blake2B (160, 256, 384, 512)` :heavy_check_mark:
 
 * `Blake2S (128, 160, 224, 256)` :heavy_check_mark:

 * `SHA-3 (224, 256, 384, 512)` :heavy_check_mark:
 
 * `Keccak (224, 256, 288, 384, 512)` :heavy_check_mark:
 
 * `Blake2BP` :heavy_check_mark:

 * `Blake2SP` :heavy_check_mark:

 * `Blake3` :heavy_check_mark:

### Key Derivation Functions
----------------------------------------

###### Password Hashing Schemes (Password Based Key Derivation Functions)

----------------------------------------

* `PBKDF2` :heavy_check_mark:
 
* `Argon2 (2i, 2d and 2id variants)` :heavy_check_mark:

* `Scrypt` :heavy_check_mark:

### MAC
----------------------------------------

* `HMAC (all supported hashes)` :heavy_check_mark:

* `KMAC (KMAC128, KMAC256)` :heavy_check_mark:

* `Blake2MAC (Blake2BMAC, Blake2SMAC)` :heavy_check_mark:

### XOF (Extendable Output Function)
----------------------------------------

* `Shake (Shake-128, Shake-256)` :heavy_check_mark:

* `CShake (CShake-128, CShake-256)` :heavy_check_mark:

* `Blake2X (Blake2XS, Blake2XB)` :heavy_check_mark:

* `KMACXOF (KMAC128XOF, KMAC256XOF)` :heavy_check_mark:

* `Blake3XOF` :heavy_check_mark:

### Usage Examples
----------------------------------------


```c#
using SharpHash.Base;
using SharpHash.Interfaces;
using System;
using System.Text;

namespace Program
{
    public class Hello 
    {
	public static void Main() 
	{
	    // Chaining mode
	    string result = HashFactory.Crypto.CreateMD5()
	    			.ComputeString("Hello C#", Encoding.UTF8).ToString();

	    // Incremental mode
	    IHash hash = HashFactory.Crypto.CreateMD5();
	    hash.Initialize();
	    hash.TransformString("Hello", Encoding.UTF8);
	    hash.TransformString(" C#", Encoding.UTF8);
	    string result_2 = hash.TransformFinal().ToString();

	    bool check = result == result_2;
	
	    // Using the HashName Builder variation
	    IHash hash_builder = HashFactory.CreateHash("md5");
	    string result_3 = hash_builder.ComputeString("Hello C#", 
				Encoding.UTF8).ToString();
	    bool check_2 = result == result_3;
	}
    }
}
```


### Other Implementations
----------------------------------------

If you want implementations in other languages, you can check out these

* [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal) by Ugochukwu Mmaduekwe
* [HashLib4CPP](https://github.com/ron4fun/HashLib4CPP) by Mbadiwe Nnaemeka Ronald
* [HashLib4Python](https://github.com/ron4fun/HashLib4Python) by Mbadiwe Nnaemeka Ronald

### Tip Jar
----------------------------------------

* :dollar: **Bitcoin**: `1Mcci95WffSJnV6PsYG7KD1af1gDfUvLe6`
