///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019 - 2020  Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/SharpHash>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
/// Also, I will like to thank Udezue Chukwunwike (https://github.com/IzarchTech) for
/// his contributions to the growth and development of this library.
///
////////////////////////////////////////////////////////////////////////

using SharpHash.Checksum;
using SharpHash.Crypto;
using SharpHash.Crypto.Blake2BConfigurations;
using SharpHash.Crypto.Blake2SConfigurations;
using SharpHash.Hash128;
using SharpHash.Hash32;
using SharpHash.Hash64;
using SharpHash.Interfaces;
using SharpHash.Interfaces.IBlake2BConfigurations;
using SharpHash.Interfaces.IBlake2SConfigurations;
using SharpHash.KDF;
using SharpHash.Utils;
using System;

namespace SharpHash.Base
{
    public static class HashFactory
    {
        public static IHash CreateHash(string hash_string) => LangBuilder.Reducer(hash_string);

        public static class NullDigestFactory
        {
            public static IHash CreateNullDigest() => new NullDigest();

        } // end class NullDigestFactory

        public static class Checksum
        {
            public static IHash CreateCRC(Int32 width, UInt64 polynomial, UInt64 initialValue,
                bool reflectIn, bool reflectOut, UInt64 outputXor, UInt64 checkValue,
                string[] Names) => new CRC(width, polynomial, initialValue, reflectIn,
                    reflectOut, outputXor, checkValue, Names);

            public static IHash CreateCRC(CRCStandard value) => CRC.CreateCRCObject(value);

            public static IHash CreateCRC16(UInt64 polynomial, UInt64 initialValue,
                bool reflectIn, bool reflectOut, UInt64 outputXor, UInt64 checkValue,
                string[] Names) => new CRC16(polynomial, initialValue, reflectIn,
                    reflectOut, outputXor, checkValue, Names);

            /// <summary>
            /// BUYPASS, polynomial = 0x8005
            /// </summary>
            /// <returns>IHash</returns>
            public static IHash CreateCRC16_BUYPASS() => new CRC16_BUYPASS();

            public static IHash CreateCRC32(UInt64 polynomial, UInt64 initialValue,
                bool reflectIn, bool reflectOut, UInt64 outputXor, UInt64 checkValue,
                string[] Names) => new CRC32(polynomial, initialValue, reflectIn,
                    reflectOut, outputXor, checkValue, Names);

            /// <summary>
            /// Castagnoli, polynomial = 0x1EDC6F41
            /// </summary>
            /// <returns>IHash</returns>
            public static IHash CreateCRC32_CASTAGNOLI() => new CRC32_CASTAGNOLI_Fast();

            /// <summary>
            /// PKZIP, polynomial = 0x04C11DB7
            /// </summary>
            /// <returns>IHash</returns>
            public static IHash CreateCRC32_PKZIP() => new CRC32_PKZIP_Fast();

            public static IHash CreateCRC64(UInt64 polynomial, UInt64 initialValue,
                bool reflectIn, bool reflectOut, UInt64 outputXor, UInt64 checkValue,
                string[] Names) => new CRC64(polynomial, initialValue, reflectIn,
                    reflectOut, outputXor, checkValue, Names);

            /// <summary>
            /// ECMA-182, polynomial = 0x42F0E1EBA9EA3693
            /// </summary>
            /// <returns>IHash</returns>
            public static IHash CreateCRC64_ECMA_182() => new CRC64_ECMA_182();

            public static IHash CreateAdler32() => new Adler32();

        } // end class Checksum

        public static class Crypto
        {
            public static IHash CreateHAS160() => new HAS160();

            public static IHash CreatePanama() => new Panama();

            public static IHash CreateWhirlPool() => new WhirlPool();

            ///////////////////////////////////////////
            /// <summary>
            /// Gost Hash Family
            /// </summary>
            ////////////////////////////////////////////

            public static IHash CreateGost() => new Gost();

            public static IHash CreateGOST3411_2012_256() => new GOST3411_2012_256();

            public static IHash CreateGOST3411_2012_512() => new GOST3411_2012_512();

            ///////////////////////////////////////////
            /// <summary>
            /// Haval Hash Family
            /// </summary>
            ////////////////////////////////////////////

            /// <summary>
            ///
            /// </summary>
            /// <param name="a_rounds">3, 4, 5</param>
            /// <param name="a_hash_size">128, 160, 192, 224, 256</param>
            /// <returns></returns>
            public static IHash CreateHaval(HashRounds a_rounds, HashSizeEnum a_hash_size)
            {
                switch (a_rounds)
                {
                    case HashRounds.Rounds3:
                        switch (a_hash_size)
                        {
                            case HashSizeEnum.HashSize128:
                                return CreateHaval_3_128();

                            case HashSizeEnum.HashSize160:
                                return CreateHaval_3_160();

                            case HashSizeEnum.HashSize192:
                                return CreateHaval_3_192();

                            case HashSizeEnum.HashSize224:
                                return CreateHaval_3_224();

                            case HashSizeEnum.HashSize256:
                                return CreateHaval_3_256();

                            default:
                                throw new ArgumentHashLibException(Haval.InvalidHavalHashSize);
                        } // end switch

                    case HashRounds.Rounds4:
                        switch (a_hash_size)
                        {
                            case HashSizeEnum.HashSize128:
                                return CreateHaval_4_128();

                            case HashSizeEnum.HashSize160:
                                return CreateHaval_4_160();

                            case HashSizeEnum.HashSize192:
                                return CreateHaval_4_192();

                            case HashSizeEnum.HashSize224:
                                return CreateHaval_4_224();

                            case HashSizeEnum.HashSize256:
                                return CreateHaval_4_256();

                            default:
                                throw new ArgumentHashLibException(Haval.InvalidHavalHashSize);
                        } // end switch

                    case HashRounds.Rounds5:
                        switch (a_hash_size)
                        {
                            case HashSizeEnum.HashSize128:
                                return CreateHaval_5_128();

                            case HashSizeEnum.HashSize160:
                                return CreateHaval_5_160();

                            case HashSizeEnum.HashSize192:
                                return CreateHaval_5_192();

                            case HashSizeEnum.HashSize224:
                                return CreateHaval_5_224();

                            case HashSizeEnum.HashSize256:
                                return CreateHaval_5_256();

                            default:
                                throw new ArgumentHashLibException(Haval.InvalidHavalHashSize);
                        } // end switch

                    default:
                        throw new ArgumentHashLibException(Haval.InvalidHavalRound);
                } // end switch
            } // end function Haval

            public static IHash CreateHaval_3_128() => new Haval_3_128();

            public static IHash CreateHaval_4_128() => new Haval_4_128();

            public static IHash CreateHaval_5_128() => new Haval_5_128();

            public static IHash CreateHaval_3_160() => new Haval_3_160();

            public static IHash CreateHaval_4_160() => new Haval_4_160();

            public static IHash CreateHaval_5_160() => new Haval_5_160();

            public static IHash CreateHaval_3_192() => new Haval_3_192();

            public static IHash CreateHaval_4_192() => new Haval_4_192();

            public static IHash CreateHaval_5_192() => new Haval_5_192();

            public static IHash CreateHaval_3_224() => new Haval_3_224();

            public static IHash CreateHaval_4_224() => new Haval_4_224();

            public static IHash CreateHaval_5_224() => new Haval_5_224();

            public static IHash CreateHaval_3_256() => new Haval_3_256();

            public static IHash CreateHaval_4_256() => new Haval_4_256();

            public static IHash CreateHaval_5_256() => new Haval_5_256();

            ///////////////////////////////////////////
            /// <summary>
            /// RadioGatun Hash Family
            /// </summary>
            ////////////////////////////////////////////

            public static IHash CreateRadioGatun32() => new RadioGatun32();

            public static IHash CreateRadioGatun64() => new RadioGatun64();

            ///////////////////////////////////////////
            /// <summary>
            /// Grindahl Hash Family
            /// </summary>
            ////////////////////////////////////////////

            public static IHash CreateGrindahl256() => new Grindahl256();

            public static IHash CreateGrindahl512() => new Grindahl512();

            ///////////////////////////////////////////
            /// <summary>
            /// RIPEMD Hash Family
            /// </summary>
            ////////////////////////////////////////////

            public static IHash CreateRIPEMD() => new RIPEMD();

            public static IHash CreateRIPEMD128() => new RIPEMD128();

            public static IHash CreateRIPEMD160() => new RIPEMD160();

            public static IHash CreateRIPEMD256() => new RIPEMD256();

            public static IHash CreateRIPEMD320() => new RIPEMD320();

            ///////////////////////////////////////////
            /// <summary>
            /// Snefru Hash Family
            /// </summary>
            ////////////////////////////////////////////

            /// <summary>
            ///
            /// </summary>
            /// <param name="a_security_level">any Integer value greater than 0. Standard is 8. </param>
            /// <param name="a_hash_size">128bit, 256bit</param>
            /// <returns></returns>
            public static IHash CreateSnefru(Int32 a_security_level, HashSizeEnum a_hash_size)
            {
                if (a_security_level < 1)
                    throw new ArgumentHashLibException(Snefru.InvalidSnefruLevel);

                if ((a_hash_size == HashSizeEnum.HashSize128) || (a_hash_size == HashSizeEnum.HashSize256))
                    return new Snefru(a_security_level, (Int32)a_hash_size);
                else
                    throw new ArgumentHashLibException(Snefru.InvalidSnefruHashSize);
            } // end function CreateSnefru

            public static IHash CreateSnefru_8_128() => CreateSnefru(8, HashSizeEnum.HashSize128);

            public static IHash CreateSnefru_8_256() => CreateSnefru(8, HashSizeEnum.HashSize256);

            ///////////////////////////////////////////
            /// <summary>
            /// MD Hash Family
            /// </summary>
            ////////////////////////////////////////////

            public static IHash CreateMD2() => new MD2();

            public static IHash CreateMD4() => new MD4();

            public static IHash CreateMD5() => new MD5();

            ///////////////////////////////////////////
            /// <summary>
            /// SHA Hash Family
            /// </summary>
            ////////////////////////////////////////////

            public static IHash CreateSHA0() => new SHA0();

            public static IHash CreateSHA1() => new SHA1();

            public static IHash CreateSHA2_224() => new SHA2_224();

            public static IHash CreateSHA2_256() => new SHA2_256();

            public static IHash CreateSHA2_384() => new SHA2_384();

            public static IHash CreateSHA2_512() => new SHA2_512();

            public static IHash CreateSHA2_512_224() => new SHA2_512_224();

            public static IHash CreateSHA2_512_256() => new SHA2_512_256();

            public static IHash CreateSHA3_224() => new SHA3_224();

            public static IHash CreateSHA3_256() => new SHA3_256();

            public static IHash CreateSHA3_384() => new SHA3_384();

            public static IHash CreateSHA3_512() => new SHA3_512();

            public static IHash CreateKeccak_224() => new Keccak_224();

            public static IHash CreateKeccak_256() => new Keccak_256();

            public static IHash CreateKeccak_288() => new Keccak_288();

            public static IHash CreateKeccak_384() => new Keccak_384();

            public static IHash CreateKeccak_512() => new Keccak_512();

            ///////////////////////////////////////////
            /// <summary>
            /// Blake Hash Family
            /// </summary>
            ////////////////////////////////////////////
            ///
            public static IHash CreateBlake2B(IBlake2BConfig a_Config = null, IBlake2BTreeConfig a_TreeConfig = null)
                => new Blake2B(a_Config ?? Blake2BConfig.DefaultConfig, a_TreeConfig);

            public static IHash CreateBlake2B_160() => CreateBlake2B(new Blake2BConfig(HashSizeEnum.HashSize160));

            public static IHash CreateBlake2B_256() => CreateBlake2B(new Blake2BConfig(HashSizeEnum.HashSize256));

            public static IHash CreateBlake2B_384() => CreateBlake2B(new Blake2BConfig(HashSizeEnum.HashSize384));

            public static IHash CreateBlake2B_512() => CreateBlake2B(new Blake2BConfig(HashSizeEnum.HashSize512));

            public static IHash CreateBlake2S(IBlake2SConfig a_Config = null, IBlake2STreeConfig a_TreeConfig = null)
                => new Blake2S(a_Config ?? Blake2SConfig.DefaultConfig, a_TreeConfig);

            public static IHash CreateBlake2S_128() => CreateBlake2S(new Blake2SConfig(HashSizeEnum.HashSize128));

            public static IHash CreateBlake2S_160() => CreateBlake2S(new Blake2SConfig(HashSizeEnum.HashSize160)); 

            public static IHash CreateBlake2S_224() => CreateBlake2S(new Blake2SConfig(HashSizeEnum.HashSize224));

            public static IHash CreateBlake2S_256() => CreateBlake2S(new Blake2SConfig(HashSizeEnum.HashSize256));

            public static IHash CreateBlake2BP(Int32 a_HashSize, byte[] a_Key) => new Blake2BP(a_HashSize, a_Key);

            public static IHash CreateBlake2SP(Int32 a_HashSize, byte[] a_Key) => new Blake2SP(a_HashSize, a_Key);

            public static IHash CreateBlake3_256(byte[] a_Key) => Blake3.CreateBlake3(HashSizeEnum.HashSize256, a_Key);

            ///////////////////////////////////////////
            /// <summary>
            /// Tiger Hash Family
            /// </summary>
            ////////////////////////////////////////////

            /// <summary>
            /// Tiger Hash
            /// </summary>
            /// <param name="a_hash_size">16, 20 or 24 bytes. </param>
            /// <param name="a_rounds">no of rounds (standard rounds are 3, 4 and 5)</param>
            /// <returns></returns>
            public static IHash CreateTiger(Int32 a_hash_size, HashRounds a_rounds)
            {
                if ((a_hash_size != 16) && (a_hash_size != 20) && (a_hash_size != 24))
                    throw new ArgumentHashLibException(Tiger.InvalidTigerHashSize);

                return new Tiger_Base(a_hash_size, a_rounds);
            } // end function CreateTiger

            public static IHash CreateTiger_3_128() => Tiger_128.CreateRound3();

            public static IHash CreateTiger_3_160() => Tiger_160.CreateRound3();

            public static IHash CreateTiger_3_192() => Tiger_192.CreateRound3();

            public static IHash CreateTiger_4_128() => Tiger_128.CreateRound4();

            public static IHash CreateTiger_4_160() => Tiger_160.CreateRound4();

            public static IHash CreateTiger_4_192() => Tiger_192.CreateRound4();

            public static IHash CreateTiger_5_128() => Tiger_128.CreateRound5();

            public static IHash CreateTiger_5_160() => Tiger_160.CreateRound5();

            public static IHash CreateTiger_5_192() => Tiger_192.CreateRound5();

            ///////////////////////////////////////////
            /// <summary>
            /// Tiger2 Hash Family
            /// </summary>
            ////////////////////////////////////////////

            /// <summary>
            /// Tiger2 Hash
            /// </summary>
            /// <param name="a_hash_size">16, 20 or 24 bytes. </param>
            /// <param name="a_rounds">no of rounds (standard rounds are 3, 4 and 5)</param>
            /// <returns></returns>
            public static IHash CreateTiger2(Int32 a_hash_size, HashRounds a_rounds)
            {
                if ((a_hash_size != 16) && (a_hash_size != 20) && (a_hash_size != 24))
                    throw new ArgumentHashLibException(Tiger2.InvalidTiger2HashSize);

                return new Tiger2_Base(a_hash_size, a_rounds);
            } // end function CreateTiger2

            public static IHash CreateTiger2_3_128() => Tiger2_128.CreateRound3();

            public static IHash CreateTiger2_3_160() => Tiger2_160.CreateRound3();

            public static IHash CreateTiger2_3_192() => Tiger2_192.CreateRound3();

            public static IHash CreateTiger2_4_128() => Tiger2_128.CreateRound4();

            public static IHash CreateTiger2_4_160() => Tiger2_160.CreateRound4();

            public static IHash CreateTiger2_4_192() => Tiger2_192.CreateRound4();

            public static IHash CreateTiger2_5_128() => Tiger2_128.CreateRound5();

            public static IHash CreateTiger2_5_160() => Tiger2_160.CreateRound5();

            public static IHash CreateTiger2_5_192() => Tiger2_192.CreateRound5();

        } // end class Crypto

        public static class Hash32
        {
            public static IHash CreateAP() => new AP();

            public static IHash CreateBernstein() => new Bernstein();

            public static IHash CreateBernstein1() => new Bernstein1();

            public static IHash CreateBKDR() => new BKDR();

            public static IHash CreateDEK() => new DEK();

            public static IHash CreateDJB() => new DJB();

            public static IHash CreateELF() => new ELF();

            public static IHash CreateFNV() => new FNV();

            public static IHash CreateFNV1a() => new FNV1a();

            public static IHash CreateJenkins3(Int32 initialValue = 0) => new Jenkins3(initialValue);

            public static IHash CreateJS() => new JS();

            public static IHashWithKey CreateMurmur2() => new Murmur2();

            public static IHashWithKey CreateMurmurHash3_x86_32() => new MurmurHash3_x86_32();

            public static IHash CreateOneAtTime() => new OneAtTime();

            public static IHash CreatePJW() => new PJW();

            public static IHash CreateRotating() => new Rotating();

            public static IHash CreateRS() => new RS();

            public static IHash CreateSDBM() => new SDBM();

            public static IHash CreateShiftAndXor() => new ShiftAndXor();

            public static IHash CreateSuperFast() => new SuperFast();

            public static IHashWithKey CreateXXHash32() => new XXHash32();

        } // end class Hash32

        public static class Hash64
        {
            public static IHash CreateFNV() => new FNV64();

            public static IHash CreateFNV1a() => new FNV1a64();

            public static IHashWithKey CreateMurmur2() => new Murmur2_64();

            public static IHashWithKey CreateSipHash64_2_4() => new SipHash64_2_4();

            public static IHashWithKey CreateXXHash64() => new XXHash64();

        } // end class Hash64

        public static class Hash128
        {
            public static IHashWithKey CreateMurmurHash3_x86_128() => new MurmurHash3_x86_128();

            public static IHashWithKey CreateMurmurHash3_x64_128() => new MurmurHash3_x64_128();

            public static IHashWithKey CreateSipHash128_2_4() => new SipHash128_2_4();

        } // end class Hash128

        public static class XOF
        {
            public static IHash CreateShake_128(UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new Shake_128() as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateShake_128

            public static IHash CreateShake_256(UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new Shake_256() as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateShake_256

            public static IHash CreateCShake_128(byte[] AN, byte[] AS, UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new CShake_128(AN, AS) as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateCShake_128

            public static IHash CreateCShake_256(byte[] AN, byte[] AS, UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new CShake_256(AN, AS) as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateCShake_256

            public static IHash CreateBlake2XS(IBlake2XSConfig a_Blake2XSConfig, UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new Blake2XS(a_Blake2XSConfig) as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateBlake2XS

            public static IHash CreateBlake2XS(byte[] a_Key, UInt64 a_XofSizeInBits)
            {
                IBlake2SConfig config = new Blake2SConfig(32);
                config.Key = a_Key.DeepCopy();

                return CreateBlake2XS(new Blake2XSConfig(config, null), a_XofSizeInBits);
            } // end function CreateBlake2XS

            public static IHash CreateBlake2XB(IBlake2XBConfig a_Blake2XBConfig, UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new Blake2XB(a_Blake2XBConfig) as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateBlake2XB

            public static IHash CreateBlake2XB(byte[] a_Key, UInt64 a_XofSizeInBits)
            {
                IBlake2BConfig config = new Blake2BConfig(64);
                config.Key = a_Key.DeepCopy();

                return CreateBlake2XB(new Blake2XBConfig(config, null), a_XofSizeInBits);
            } // end function CreateBlake2XB

            public static IHash CreateBlake3XOF(byte[] a_Key, UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (Blake3XOF.CreateBlake3XOF(32, a_Key) as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateBlake3XOF

            public static IHash CreateKMAC128XOF(byte[] a_KMACKey, byte[] a_Customization,
                        UInt64 a_XofSizeInBits) 
                => KMAC128XOF.CreateKMAC128XOF(a_KMACKey, a_Customization, a_XofSizeInBits);

            public static IHash CreateKMAC256XOF(byte[] a_KMACKey, byte[] a_Customization,
                UInt64 a_XofSizeInBits) 
                => KMAC256XOF.CreateKMAC256XOF(a_KMACKey, a_Customization, a_XofSizeInBits);

        } // end class XOF

        public static class KMAC
        {
            public static IHash CreateKMAC128(byte[] a_KMACKey, byte[] a_Customization,
                UInt64 a_OutputLengthInBits) 
                => KMAC128.CreateKMAC128(a_KMACKey, a_Customization, a_OutputLengthInBits);

            public static IHash CreateKMAC256(byte[] a_KMACKey, byte[] a_Customization,
                UInt64 a_OutputLengthInBits) 
                => KMAC256.CreateKMAC256(a_KMACKey, a_Customization, a_OutputLengthInBits);

        } // end class KMAC

        public static class HMAC
        {
            public static IHMAC CreateHMAC(IHash hash, byte[] a_HMACKey) 
                => HMACNotBuildInAdapter.CreateHMAC(hash, a_HMACKey);

        } // end class HMAC

        public static class Blake2BMAC
        {
            public static IBlake2BMAC CreateBlake2BMAC(byte[] a_Blake2BKey, byte[] a_Salt, byte[] a_Personalisation, Int32 a_OutputLengthInBits)
                => Blake2BMACNotBuildInAdapter.CreateBlake2BMAC(a_Blake2BKey, a_Salt,
                    a_Personalisation, a_OutputLengthInBits);

        } // end class Blake2BMAC

        public static class Blake2SMAC
        {
            public static IBlake2SMAC CreateBlake2SMAC(byte[] a_Blake2SKey, byte[] a_Salt, byte[] a_Personalisation, Int32 a_OutputLengthInBits)
                => Blake2SMACNotBuildInAdapter.CreateBlake2SMAC(a_Blake2SKey, a_Salt,
                    a_Personalisation, a_OutputLengthInBits);

        } // end class Blake2SMAC

        public static class KDF
        {
            public static class PBKDF2_HMAC
            {
                /// <summary>
                /// Initializes a new interface instance of the TPBKDF2_HMAC class using a password, a salt, a number of iterations and an Instance of an "IHash" to be used as an "IHMAC" hashing implementation to derive the key.
                /// </summary>
                /// <param name="a_hash">The name of the "IHash" implementation to be transformed to an "IHMAC" Instance so it can be used to derive the key.</param>
                /// <param name="a_password">The password to derive the key for.</param>
                /// <param name="a_salt">The salt to use to derive the key.</param>
                /// <param name="a_iterations">The number of iterations to use to derive the key.</param>
                /// <exception cref="ArgumentNullHashLibException">The password, salt or algorithm is Nil.</exception>
                /// <exception cref="ArgumentHashLibException">The iteration is less than 1.</exception>
                public static IPBKDF2_HMAC CreatePBKDF2_HMAC(IHash a_hash, byte[] a_password,
                    byte[] a_salt, UInt32 a_iterations)
                {
                    if (a_hash == null)
                        throw new ArgumentNullHashLibException(PBKDF2_HMACNotBuildInAdapter.UninitializedInstance);

                    if (a_password.Empty())
                        throw new ArgumentNullHashLibException(PBKDF2_HMACNotBuildInAdapter.EmptyPassword);

                    if (a_salt.Empty())
                        throw new ArgumentNullHashLibException(PBKDF2_HMACNotBuildInAdapter.EmptySalt);

                    if (a_iterations < 1)
                        throw new ArgumentHashLibException(PBKDF2_HMACNotBuildInAdapter.IterationTooSmall);

                    return new PBKDF2_HMACNotBuildInAdapter(a_hash, a_password, a_salt, a_iterations);
                } // end function CreatePBKDF2_HMAC
            } // end class PBKDF2_HMAC

            public static class PBKDF_Blake3
            {
                public static IPBKDF_Blake3NotBuiltIn CreatePBKDF_Blake3(byte[] a_key, byte[] ctx) 
                    => new PBKDF_Blake3NotBuiltInAdapter(a_key, ctx);

            } // end class PBKDF_Blake3

            public static class PBKDF_Argon2
            {
                public static IPBKDF_Argon2 CreatePBKDF_Argon2(byte[] a_Password, IArgon2Parameters a_Argon2Parameters)
                    => new PBKDF_Argon2NotBuildInAdapter(a_Password, a_Argon2Parameters);

            } // end class PBKDF_Argon2

            public static class PBKDF_Scrypt
            {
                public static IPBKDF_Scrypt CreatePBKDF_Scrypt(byte[] a_PasswordBytes,
                    byte[] a_SaltBytes, Int32 a_Cost, Int32 a_BlockSize, Int32 a_Parallelism) 
                    => new PBKDF_ScryptNotBuildInAdapter(a_PasswordBytes, a_SaltBytes,
                        a_Cost, a_BlockSize, a_Parallelism);

            } // end class PBKDF_Scrypt

        } // end class KDF

    } // end class HashFactory
}