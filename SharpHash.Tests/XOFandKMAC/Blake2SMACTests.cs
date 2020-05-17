using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.Linq;
using System.Text;

namespace SharpHash.XOFandKMAC.Tests
{
    [TestClass]
    public class Blake2SMACTests
    {
        private void DoComputeBlake2SMAC(string a_Key, string a_Personalisation, string a_Salt, string a_Data,
            string a_ExpectedResult, Int32 a_OutputSizeInBits)
        {
            IHash LHash, LClone;
            Int32 LIdx;
            byte[] ActualResult, ActualResultClone, Key, Salt, Personalisation, Data;

            Key = Converters.ConvertHexStringToBytes(a_Key);
            Personalisation = Converters.ConvertStringToBytes(a_Personalisation, Encoding.UTF8);

            // if personalisation length != 8, resize to 8, padding with zeros if necessary
            if (Personalisation.Length != 8)
                Array.Resize(ref Personalisation, 8);

            Salt = Converters.ConvertHexStringToBytes(a_Salt);
            Data = Converters.ConvertStringToBytes(a_Data, Encoding.UTF8);

            LHash = HashFactory.Blake2SMAC.CreateBlake2SMAC(Key, Salt, Personalisation, a_OutputSizeInBits);

            LHash.Initialize();

            for (LIdx = 0; LIdx < Data.Length; LIdx++)
                LHash.TransformBytes(new byte[] { Data[LIdx] }); // do incremental hashing

            LClone = LHash.Clone();

            ActualResult = LHash.TransformFinal().GetBytes();
            ActualResultClone = LClone.TransformFinal().GetBytes();

            Assert.AreEqual(a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResult, false),
                String.Format("Expected {0} But got {1}", a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResult, false)));

            if (!ActualResult.SequenceEqual(ActualResultClone))
            {
                Assert.Fail(String.Format(
                    "Blake2SMAC mismatch on test vector against a clone, Expected \"{0}\" but got \"{1}\"",
                    a_ExpectedResult, Converters.ConvertBytesToHexString(ActualResultClone, false)));
            }

        } // end function DoComputeKMAC128

        [TestMethod]
        public void TestBlake2SMACSample1()
        {
            DoComputeBlake2SMAC("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "", "",
                "Sample input for outlen<digest_length", "07", 1 * 8);
        }

        [TestMethod]
        public void TestBlake2SMACSample2()
        {
            DoComputeBlake2SMAC("000102030405060708090A0B0C0D0E0F", "app",
                "0001020304050607", "Combo input with outlen, custom and salt",
                "6808D8DAAE537A16BF00E837010969A4", 16 * 8);
        }

        [TestMethod]
        public void TestBlake2SMACSample3()
        {
            DoComputeBlake2SMAC("000102030405060708090A0B0C0D0E0F", "app", 
                "A205819E78D6D762", "Sample input for keylen<blocklen, salt and custom",
                "E9F7704DFE5080A4AAFE62A806F53EA7F98FFC24175164158F18EC5497B961F5", 32 * 8);
        }

    }
}