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
    public class SHA2_224Tests
    {
        protected IHash hash = new SHA2_224();

        protected string ExpectedHashOfEmptyData = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
        protected string ExpectedHashOfDefaultData = "DF2B86ED008508F542443C4B1810AA5A0F5658692B808EEB1D0A2F7E";
        protected string ExpectedHashOfOnetoNine = "9B3E61BF29F17C75572FAE2E86E17809A4513D07C8A18152ACF34521";
        protected string ExpectedHashOfabcde = "BDD03D560993E675516BA5A50638B6531AC2AC3D5847C61916CFCED6";
        protected string ExpectedHashOfDefaultDataWithHMACWithLongKey = "86855E59D8B09A3C7632D4E176C4B65C549255F417FEF9EEF2D4167D";
        protected string ExpectedHashOfDefaultDataWithHMACWithShortKey = "EC47E83DB5DD735EBB7AA4A898460950B16A3A0FA48E4BB9184EA3D1";

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
