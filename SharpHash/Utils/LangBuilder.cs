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

using SharpHash.Base;
using SharpHash.Checksum;
using SharpHash.Crypto;
using SharpHash.Crypto.Blake2BConfigurations;
using SharpHash.Crypto.Blake2SConfigurations;
using SharpHash.Hash128;
using SharpHash.Hash32;
using SharpHash.Hash64;
using SharpHash.Interfaces;

namespace SharpHash.Utils
{
    internal static class LangBuilder
    {
        /// <summary>
        /// Return IHash instance of the requested hash string
        /// </summary>
        /// <param name="hash_string"></param>
        /// <returns></returns>
        public static IHash Reducer(string hash_string)
        {
            return Core(hash_string);
        }

        private static string Strip(string hash_string)
        {
            return hash_string
                .Trim()
                .Replace(" ", "")
                .Replace("_", "")
                .Replace("-", "")
                .ToLower();
        }

        private static IHash Core(string hash_string)
        {
            string hash = Strip(hash_string);

            switch (hash)
            {
                #region NullDigest
                case "nulldigest":
                    return new NullDigest();
                #endregion

                #region Checksum
                case "crc16":
                case "crcbuypass":
                case "crc16buypass":
                    return new CRC16_BUYPASS();              
                case "crc32":
                case "crcpkzip":
                case "crc32pkzip":
                    return new CRC32_PKZIP();
                case "crccastagnoli":
                case "crc32castagnoli":
                    return new CRC32_CASTAGNOLI();
                case "crc64":
                case "crcecma":
                case "crc64ecma":
                case "crc64ecma182":
                    return new CRC64_ECMA_182();
                case "adler":
                case "adler32":
                    return new Adler32();
                #endregion

                #region Crypto
                case "has160":
                    return new HAS160();
                case "panama":
                    return new Panama();
                case "whirlpool":
                    return new WhirlPool();

                #region Gost Hash Family
                case "gost":
                    return new Gost();                    
                case "gost256":
                case "gost2012":
                case "gost2012256":
                case "gost2562012":
                case "gost34112012256":
                    return new GOST3411_2012_256();
                case "gost512":
                case "gost2012512":
                case "gost5122012":
                case "gost34112012512":
                    return new GOST3411_2012_512();
                #endregion

                #region Haval Hash Family
                case "haval3128":
                    return new Haval_3_128();
                case "haval4128":
                    return new Haval_4_128();
                case "haval5128":
                    return new Haval_5_128();
                case "haval3160":
                    return new Haval_3_160();
                case "haval4160":
                    return new Haval_4_160();
                case "haval5160":
                    return new Haval_5_160();
                case "haval3192":
                    return new Haval_3_192();
                case "haval4192":
                    return new Haval_4_192();
                case "haval5192":
                    return new Haval_5_192();
                case "haval3224":
                    return new Haval_3_224();
                case "haval4224":
                    return new Haval_4_224();
                case "haval5224":
                    return new Haval_5_224();
                case "haval3256":
                    return new Haval_3_256();
                case "haval4256":
                    return new Haval_4_256();
                case "haval5256":
                    return new Haval_5_256();
                #endregion

                #region RadioGatun Hash Family
                case "radiogatun":
                case "radiogatun32":
                    return new RadioGatun32();
                case "radiogatun64":
                    return new RadioGatun64();
                #endregion

                #region Grindahl Hash Family
                case "grindahl":
                case "grindahl256":
                    return new Grindahl256();
                case "grindahl512":
                    return new Grindahl512();
                #endregion

                #region RIPEMD Hash Family
                case "ripemd":
                    return new RIPEMD();
                case "ripemd128":
                    return new RIPEMD128();
                case "ripemd160":
                    return new RIPEMD160();
                case "ripemd256":
                    return new RIPEMD256();
                case "ripemd320":
                    return new RIPEMD320();
                #endregion

                #region Snefru Hash Family
                case "snefru":
                case "snefru8128":
                    return new Snefru(8, 128);
                case "snefru8256":
                    return new Snefru(8, 256);
                #endregion

                #region MD Hash Family
                case "md2":
                    return new MD2();
                case "md4":
                    return new MD4();
                case "md5":
                    return new MD5();
                #endregion

                #region SHA Hash Family
                case "sha0":
                    return new SHA0();
                case "sha1":
                    return new SHA1();
                case "sha2224":
                    return new SHA2_224();
                case "sha2256":
                    return new SHA2_256();
                case "sha2384":
                    return new SHA2_384();
                case "sha2512":
                    return new SHA2_512();
                case "sha2512224":
                    return new SHA2_512_224();
                case "sha2512256":
                    return new SHA2_512_256();
                case "sha3224":
                    return new SHA3_224();
                case "sha3256":
                    return new SHA3_256();
                case "sha3384":
                    return new SHA3_384();
                case "sha3512":
                    return new SHA3_512();
                case "keccak224":
                    return new Keccak_224();
                case "keccak256":
                    return new Keccak_256();
                case "keccak288":
                    return new Keccak_288();
                case "keccak384":
                    return new Keccak_384();
                case "keccak512":
                    return new Keccak_512();
                #endregion

                #region Blake Hash Family
                case "blake2b":
                    return new Blake2B(new Blake2BConfig(), null);
                case "blake2b160":
                    return new Blake2B(new Blake2BConfig(HashSizeEnum.HashSize160), null);
                case "blake2b256":
                    return new Blake2B(new Blake2BConfig(HashSizeEnum.HashSize256), null);
                case "blake2b384":
                    return new Blake2B(new Blake2BConfig(HashSizeEnum.HashSize384), null);
                case "blake2b512":
                    return new Blake2B(new Blake2BConfig(HashSizeEnum.HashSize512), null);
               
                case "blake2s":
                    return new Blake2S(new Blake2SConfig(), null);
                case "blake2s128":
                    return new Blake2S(new Blake2SConfig(HashSizeEnum.HashSize128), null);
                case "blake2s160":
                    return new Blake2S(new Blake2SConfig(HashSizeEnum.HashSize160), null);
                case "blake2s224":
                    return new Blake2S(new Blake2SConfig(HashSizeEnum.HashSize224), null);
                case "blake2s256":
                    return new Blake2S(new Blake2SConfig(HashSizeEnum.HashSize256), null);

                case "blake3":
                case "blake3256":
                    return Blake3.CreateBlake3(HashSizeEnum.HashSize256, null);

                #endregion

                #region Tiger Hash Family
                case "tiger3128":
                    return Tiger_128.CreateRound3();
                case "tiger3160":
                    return Tiger_160.CreateRound3();
                case "tiger3192":
                    return Tiger_192.CreateRound3();
                case "tiger4128":
                    return Tiger_128.CreateRound4();
                case "tiger4160":
                    return Tiger_160.CreateRound4();
                case "tiger4192":
                    return Tiger_192.CreateRound4();
                case "tiger5128":
                    return Tiger_128.CreateRound5();
                case "tiger5160":
                    return Tiger_160.CreateRound5();
                case "tiger5192":
                    return Tiger_192.CreateRound5();
                #endregion

                #region Tiger2 Hash Family
                case "tiger23128":
                    return Tiger2_128.CreateRound3();
                case "tiger23160":
                    return Tiger2_160.CreateRound3();
                case "tiger23192":
                    return Tiger2_192.CreateRound3();
                case "tiger24128":
                    return Tiger2_128.CreateRound4();
                case "tiger24160":
                    return Tiger2_160.CreateRound4();
                case "tiger24192":
                    return Tiger2_192.CreateRound4();
                case "tiger25128":
                    return Tiger2_128.CreateRound5();
                case "tiger25160":
                    return Tiger2_160.CreateRound5();
                case "tiger25192":
                    return Tiger2_192.CreateRound5();
                #endregion

                #endregion

                #region Hash32
                case "ap":
                    return new AP();
                case "bernstein":
                    return new Bernstein();
                case "bernstein1":
                    return new Bernstein1();
                case "bkdr":
                    return new BKDR();
                case "dek":
                    return new DEK();
                case "djb":
                    return new DJB();
                case "elf":
                    return new ELF();
                case "fnv":
                    return new FNV();
                case "fnv1a":
                    return new FNV1a();
                case "jenkins3":
                    return new Jenkins3();
                case "js":
                    return new JS();
                case "murmur2":
                    return new Murmur2();
                case "murmurhash332":
                case "murmurhash332x86":
                case "murmurhash3x8632":
                    return new MurmurHash3_x86_32();
                case "oneattime":
                    return new OneAtTime();
                case "pjw":
                    return new PJW();
                case "rotating":
                    return new Rotating();
                case "rs":
                    return new RS();
                case "sdbm":
                    return new SDBM();
                case "shiftandxor":
                    return new ShiftAndXor();
                case "superfast":
                    return new SuperFast();
                case "xxhash32":
                    return new XXHash32();
                #endregion

                #region Hash64
                case "fnv64":
                    return new FNV64();
                case "fnv1a64":
                    return new FNV1a64();
                case "murmur264":
                    return new Murmur2_64();
                case "siphash64":
                case "siphash6424":
                    return new SipHash64_2_4();
                case "xxhash64":
                    return new XXHash64();
                #endregion

                #region Hash128
                case "murmurhash3128":
                case "murmurhash3128x86":
                case "murmurhash3x86128":
                    return new MurmurHash3_x86_128();
                case "murmurhash3128x64":
                case "murmurhash3x64128":
                    return new MurmurHash3_x64_128();
                case "siphash128":
                case "siphash12824":
                    return new SipHash64_2_4();
                #endregion

            }

            throw new NotImplementedHashLibException($"Hash string: \"{hash_string}\" is unknown or not in correct format.");
        }
    }
}
