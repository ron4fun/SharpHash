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
    public class Keccak_288Tests
    {
        protected IHash hash = new Keccak_288();

        protected string ExpectedHashOfEmptyData = "6753E3380C09E385D0339EB6B050A68F66CFD60A73476E6FD6ADEB72F5EDD7C6F04A5D01";
        protected string ExpectedHashOfDefaultData = "A81F64CA8FAFFA1FC64A8E40E3F6A6FEA3303753B8F7F25E7E6EABA3D99A13F1EDF0F125";
        protected string ExpectedHashOfOnetoNine = "2B87D3D1907AA78236C7037752CA8C456611C24CE8FBAAAC961AABF3137B471C93A8F031";
        protected string ExpectedHashOfabcde = "F996518E4703A5D660B250D720A143B0A44C5DE31819A82FEF0F30158D18E74E6DF405F6";
        protected string ExpectedHashOfDefaultDataWithHMACWithLongKey = "EDC893C0E0E9E70F299098D5049D82EE6811582B93B5C38A5DC9FD14F984A352042365D0";
        protected string ExpectedHashOfDefaultDataWithHMACWithShortKey = "615143BAA85817D4F6F051E33801A900AEA480E716A01826E1392743A92B46EED587E9F7";

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
