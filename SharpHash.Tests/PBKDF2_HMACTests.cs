using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace SharpHash.Tests
{
    // ====================== PBKDF2_HMACSHA1TestCase ======================
    ////////////////////
    // PBKDF2_HMACSHA1 
    ///////////////////
    [TestClass]
    public class PBKDF2_HMACSHA1TestCase
    {
        private string ExpectedString = "BFDE6BE94DF7E11DD409BCE20A0255EC327CB936FFE93643";
        byte[] Password = new byte[] { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64 };
        byte[] Salt = new byte[] { 0x78, 0x57, 0x8E, 0x5A, 0x5D, 0x63, 0xCB, 0x06 };
        IHash hash = HashFactory.Crypto.CreateSHA1();

        [TestMethod]
        public void TestOne()
        {
            IPBKDF2_HMAC PBKDF2 = HashFactory.PBKDF2_HMAC.CreatePBKDF2_HMAC(hash, Password, Salt, 2048);
            byte[] Key = PBKDF2.GetBytes(24);
            PBKDF2.Clear();

            string ActualString = Converters.ConvertBytesToHexString(Key, false);

            Assert.AreEqual(ExpectedString, ActualString);
        }

    }

    // ====================== PBKDF2_HMACSHA2_256TestCase ======================
    ////////////////////
    // PBKDF2_HMACSHA2_256 
    ///////////////////
    [TestClass]
    public class PBKDF2_HMACSHA2_256TestCase
    {
        private string ExpectedString = "0394A2EDE332C9A13EB82E9B24631604C31DF978B4E2F0FBD2C549944F9D79A5";
        private byte[] Password = Converters.ConvertStringToBytes("password");
        private byte[] Salt = Converters.ConvertStringToBytes("salt");
        private IHash hash = HashFactory.Crypto.CreateSHA2_256();

        [TestMethod]
        public void TestOne()
        {
            IPBKDF2_HMAC PBKDF2 = HashFactory.PBKDF2_HMAC.CreatePBKDF2_HMAC(hash, Password, Salt, 100000);
            byte[] Key = PBKDF2.GetBytes(32);
            PBKDF2.Clear();

            string ActualString = Converters.ConvertBytesToHexString(Key, false);

            Assert.AreEqual(ExpectedString, ActualString);
        }

    }

}
