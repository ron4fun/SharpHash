using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using SharpHash.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA3_256Tests
    {
        protected IHash hash = new SHA3_256();

        protected string ExpectedHashOfEmptyData = "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A";
        protected string ExpectedHashOfDefaultData = "C334674D808EBB8B7C2926F043D1CAE78D168A05B70B9210C9167EA6DC300CE2";
        protected string ExpectedHashOfOnetoNine = "87CD084D190E436F147322B90E7384F6A8E0676C99D21EF519EA718E51D45F9C";
        protected string ExpectedHashOfabcde = "D716EC61E18904A8F58679B71CB065D4D5DB72E0E0C3F155A4FEFF7ADD0E58EB";
        protected string ExpectedHashOfDefaultDataWithHMACWithLongKey = "B8EC49AF4DE71CB0561A9F0DF7B156CC7784AC044F12B65048CE6DBB27A57E66";
        protected string ExpectedHashOfDefaultDataWithHMACWithShortKey = "1019B70021A038345192F00D02E33FA4AF8949E80AD592C4671A438DCCBCFBDF";

        [TestMethod]
        public void TestEmptyString()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.EmptyData,
                ExpectedHashOfEmptyData, hash);
        }

        [TestMethod]
        public void TestDefaultData()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.DefaultData,
                ExpectedHashOfDefaultData, hash);
        }

        [TestMethod]
        public void TestOnetoNine()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.OnetoNine,
                ExpectedHashOfOnetoNine, hash);
        }

        [TestMethod]
        public void TestBytesabcde()
        {
            TestHelper.TestActualAndExpectedData(TestConstants.Bytesabcde,
                ExpectedHashOfabcde, hash);
        }

        [TestMethod]
        public void TestEmptyStream()
        {
            TestHelper.TestEmptyStream(ExpectedHashOfEmptyData, hash);
        }

        [TestMethod]
        public void TestIncrementalHash()
        {
            TestHelper.TestIncrementalHash(TestConstants.DefaultData,
                ExpectedHashOfDefaultData, hash);
        }

        [TestMethod]
        public void TestHashCloneIsCorrect()
        {
            TestHelper.TestHashCloneIsCorrect(hash);
        }

        [TestMethod]
        public void TestHashCloneIsUnique()
        {
            TestHelper.TestHashCloneIsUnique(hash);
        }

        public void TestHMACWithDefaultDataAndLongKey()
        {
            IHMAC hmac = new HMACNotBuildInAdapter(hash);
            hmac.Key = Converters.ConvertStringToBytes(TestConstants.HMACLongStringKey);
            string ActualString = hmac.ComputeString(TestConstants.DefaultData).ToString();

            Assert.AreEqual(ExpectedHashOfDefaultDataWithHMACWithLongKey, ActualString);
        }

        public void TestHMACWithDefaultDataAndShortKey()
        {
            IHMAC hmac = new HMACNotBuildInAdapter(hash);
            hmac.Key = Converters.ConvertStringToBytes(TestConstants.HMACShortStringKey);
            string ActualString = hmac.ComputeString(TestConstants.DefaultData).ToString();

            Assert.AreEqual(ExpectedHashOfDefaultDataWithHMACWithShortKey, ActualString);
        }

        public void TestHMACCloneIsCorrect()
        {
            TestHelper.TestHMACCloneIsCorrect(hash);
        }

    }

}
