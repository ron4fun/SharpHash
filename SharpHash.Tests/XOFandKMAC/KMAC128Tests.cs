using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash.XOFandKMAC.Tests
{
    [TestClass]
    public class KMAC128Tests : KMACTests
    {
        private readonly UInt64 OutputSizeInBits = 32 * 8;

        public KMAC128Tests()
        {
            Int32 LIdx;
            byte[] temp = new byte[200];
            for (LIdx = 0; LIdx < temp.Length; LIdx++)
                temp[LIdx] = (byte)LIdx;

            Data = Converters.ConvertBytesToHexString(temp, false);
        } //

        private void DoComputeKMAC128(string a_Key, string a_Customization, string a_Data,
            string a_ExpectedResult, UInt64 a_OutputSizeInBits, bool IsXOF)
        {
            IHash LHash, LClone;
            Int32 LIdx;
            byte[] ActualResult, ActualResultClone, LKey, LCustomization, LData;
            string Suffix;

            LKey = Converters.ConvertHexStringToBytes(a_Key);
            LCustomization = Converters.ConvertStringToBytes(a_Customization, Encoding.UTF8);
            LData = Converters.ConvertHexStringToBytes(a_Data);

            if (IsXOF)
            {
                LHash = HashFactory.XOF.CreateKMAC128XOF(LKey, LCustomization, a_OutputSizeInBits);
                Suffix = "XOF";
            } // end if
            else
            {
                LHash = HashFactory.KMAC.CreateKMAC128(LKey, LCustomization, a_OutputSizeInBits);
                Suffix = "";
            } // end else

            LHash.Initialize();

            for (LIdx = 0; LIdx < LData.Length; LIdx++)
                LHash.TransformBytes(new byte[] { LData[LIdx] }); // do incremental hashing

            LClone = LHash.Clone();

            if (IsXOF)
            {
                ActualResult = new byte[a_OutputSizeInBits >> 3];
                ActualResultClone = new byte[a_OutputSizeInBits >> 3];

                ((LHash as IKMAC) as IXOF).DoOutput(ref ActualResult, 0, a_OutputSizeInBits >> 3);

                ((LClone as IKMAC) as IXOF).DoOutput(ref ActualResultClone, 0,
                    a_OutputSizeInBits >> 3);

                LHash.Initialize();
                LClone.Initialize();
            } // end if
            else
            {
                ActualResult = LHash.TransformFinal().GetBytes();
                ActualResultClone = LClone.TransformFinal().GetBytes();
            } // end else

            Assert.AreEqual(a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResult, false),
                String.Format("Expected {0} But got {1}", a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResult, false)));

            Assert.AreEqual(a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResultClone, false),
                String.Format("KMAC128{0} mismatch on test vector test vector against a clone, Expected \"{1}\" but got \"{2}\"",
                Suffix, a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResultClone, false)));
        } // end function DoComputeKMAC128

        [TestMethod]
        public void TestKMAC128NISTSample1()
        {
            DoComputeKMAC128(RawKeyInHex, "", TestConstants.ZeroToThreeInHex,
                "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E",
                OutputSizeInBits, false);
        }

        [TestMethod]
        public void TestKMAC128NISTSample2()
        {
            DoComputeKMAC128(RawKeyInHex, CustomizationMessage, TestConstants.ZeroToThreeInHex,
                "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5",
                OutputSizeInBits, false);
        }

        [TestMethod]
        public void TestKMAC128NISTSample3()
        {
            DoComputeKMAC128(RawKeyInHex, CustomizationMessage, Data,
                "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230",
                OutputSizeInBits, false);
        }

        [TestMethod]
        public void TestKMAC128XOFNISTSample1()
        {
            DoComputeKMAC128(RawKeyInHex, "", TestConstants.ZeroToThreeInHex,
                 "CD83740BBD92CCC8CF032B1481A0F4460E7CA9DD12B08A0C4031178BACD6EC35",
                 OutputSizeInBits, true);
        }

        [TestMethod]
        public void TestKMAC128XOFNISTSample2()
        {
            DoComputeKMAC128(RawKeyInHex, CustomizationMessage, TestConstants.ZeroToThreeInHex,
                "31A44527B4ED9F5C6101D11DE6D26F0620AA5C341DEF41299657FE9DF1A3B16C",
                OutputSizeInBits, true);
        }

        [TestMethod]
        public void TestKMAC128XOFNISTSample3()
        {
            DoComputeKMAC128(RawKeyInHex, CustomizationMessage, Data,
                 "47026C7CD793084AA0283C253EF658490C0DB61438B8326FE9BDDF281B83AE0F",
                 OutputSizeInBits, true);
        }
    }
}