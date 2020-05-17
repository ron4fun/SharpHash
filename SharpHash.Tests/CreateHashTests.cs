using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpHash.Tests
{
    [TestClass]
    public class CreateHashTests
    {
        static Dictionary<string, string[]> hashStrings = new Dictionary<string, string[]>
        {
            { "NullDigest", new string[] {"Null digest", "Null Digest", "NullDigest", "nulldigest", "NuLl_DiGeSt" } },

            { "CRC16_BUYPASS", new string[] {"Crc 16", "CRC_Buypass", "CRC 16 Buypass", "crc16buypass", "crcbuypass" } },
            { "CRC32_PKZIP", new string[] {"Crc 32", "CRC_Pkzip", "CRC 32 Pkzip", "crc32pkzip", "crcpkzip" } },
            { "CRC32_CASTAGNOLI", new string[] {"Crc 32 castagnoli", "CRC32 Castagnoli", "Crc32Castagnoli", "crc32castagnoli", "CrC32_CaStAgNoLi" } },
            { "CRC64_ECMA_182", new string[] { "Crc 64", "CRC_Ecma", "CRC 64 Ecma", "crc64ecma", "crc64ecma182", "CRC64_ECMA_182" } },
            { "Adler32", new string[] {"Adler 32", "Adler", "adler", "adler_32", "AdLeR_32" } },

            { "HAS160", new string[] { "Has 160", "Has160", "HAS_160", "has 160", "has160" } },
            { "Panama", new string[] { "PANAMA", "panama" } },
            { "WhirlPool", new string[] { "Whirl Pool", "Whirl_Pool", "whirlpool", "WHIRLPOOL", "WHIRL POOL" } },

            { "Gost", new string[] { "GOST", "gost" } },
            { "GOST3411_2012_256", new string[] {"Gost 256", "Gost 2012", "Gost 2012 256", "Gost 256 2012", "Gost 3411 2012 256" } },
            { "GOST3411_2012_512", new string[] { "Gost 512", "Gost 2012 512", "Gost 512 2012", "Gost 3411 2012 512" } },
             
            { "Haval_3_128", new string[] {"Haval 3 128", "Haval_3_128", "HAVAL3128", "haval3128" } },
            { "Haval_4_128", new string[] {"Haval 4 128", "Haval_4_128", "HAVAL4128", "haval4128" } },
            { "Haval_5_128", new string[] {"Haval 5 128", "Haval_5_128", "HAVAL5128", "haval5128" } },
            { "Haval_3_160", new string[] {"Haval 3 160", "Haval_3_160", "HAVAL3160", "haval3160" } },
            { "Haval_4_160", new string[] {"Haval 4 160", "Haval_4_160", "HAVAL4160", "haval4160" } },
            { "Haval_5_160", new string[] {"Haval 5 160", "Haval_5_160", "HAVAL5160", "haval5160" } },
            { "Haval_3_192", new string[] {"Haval 3 192", "Haval_3_192", "HAVAL3192", "haval3192" } },
            { "Haval_4_192", new string[] {"Haval 4 192", "Haval_4_192", "HAVAL4192", "haval4192" } },
            { "Haval_5_192", new string[] {"Haval 5 192", "Haval_5_192", "HAVAL5192", "haval5192" } },
            { "Haval_3_224", new string[] { "Haval 3 224", "Haval_3_224", "HAVAL3224", "haval3224" } },
            { "Haval_4_224", new string[] { "Haval 4 224", "Haval_4_224", "HAVAL4224", "haval4224" } },
            { "Haval_5_224", new string[] { "Haval 5 224", "Haval_5_224", "HAVAL5224", "haval5224" } },
            { "Haval_3_256", new string[] { "Haval 3 256", "Haval_3_256", "HAVAL3256", "haval3256" } },
            { "Haval_4_256", new string[] { "Haval 4 256", "Haval_4_256", "HAVAL4256", "haval4256" } },
            { "Haval_5_256", new string[] { "Haval 5 256", "Haval_5_256", "HAVAL5256", "haval5256" } },

            { "RadioGatun32", new string[] { "Radio Gatun 32", "Radiogatun_32", "RadioGatun", "RADIOGATUN32" } },
            { "RadioGatun64", new string[] { "Radio Gatun 64", "Radiogatun_64", "Radiogatun 64", "RADIOGATUN64" } },

            //{ "NullDigest", new string[] {"Null digest", "Null Digest", "NullDigest", "nulldigest", "NuLl_DiGeSt" } },
        };

        [TestMethod]
        public void TestAll()
        {
            foreach(var actual_string in hashStrings.Keys)
            {
                foreach (var text in hashStrings[actual_string])
                {
                    IHash hash = HashFactory.CreateHash(text);

                    Assert.AreEqual(hash.Name, actual_string,
                         string.Format("Expected {0} but got {1}.",
                         hash.Name, actual_string));
                }
            }         
        }
    }
}