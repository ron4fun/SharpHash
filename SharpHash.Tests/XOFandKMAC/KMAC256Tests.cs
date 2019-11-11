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
    public class KMAC256Tests : KMACBaseTests
    {
        private readonly UInt64 OutputSizeInBits = 64 * 8;

        public KMAC256Tests()
        {
            Int32 LIdx;
            byte[] temp = new byte[200];
            for (LIdx = 0; LIdx < temp.Length; LIdx++)
                temp[LIdx] = (byte)LIdx;

            Data = Converters.ConvertBytesToHexString(temp, false);
        } //

        private void DoComputeKMAC256(string a_Key, string a_Customization, string a_Data,
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
                LHash = HashFactory.XOF.CreateKMAC256XOF(LKey, LCustomization, a_OutputSizeInBits);
                Suffix = "XOF";
            } // end if
            else
            {
                LHash = HashFactory.KMAC.CreateKMAC256(LKey, LCustomization, a_OutputSizeInBits);
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
                String.Format("KMAC256{0} mismatch on test vector test vector against a clone, Expected \"{1}\" but got \"{2}\"",
                Suffix, a_ExpectedResult,
                Converters.ConvertBytesToHexString(ActualResultClone, false)));
        } // end function DoComputeKMAC256

        [TestMethod]
        public void TestKMAC256NISTSample1()
        {
            DoComputeKMAC256(RawKeyInHex, CustomizationMessage, TestConstants.ZeroToThreeInHex,
                "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD",
                OutputSizeInBits, false);
        }

        [TestMethod]
        public void TestKMAC256NISTSample2()
        {
            DoComputeKMAC256(RawKeyInHex, "", Data,
                "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69",
                OutputSizeInBits, false);
        }

        [TestMethod]
        public void TestKMAC256NISTSample3()
        {
            DoComputeKMAC256(RawKeyInHex, CustomizationMessage, Data,
                "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965",
                OutputSizeInBits, false);
        }

        [TestMethod]
        public void TestKMAC256XOFNISTSample1()
        {
            DoComputeKMAC256(RawKeyInHex, CustomizationMessage, TestConstants.ZeroToThreeInHex,
                 "1755133F1534752AAD0748F2C706FB5C784512CAB835CD15676B16C0C6647FA96FAA7AF634A0BF8FF6DF39374FA00FAD9A39E322A7C92065A64EB1FB0801EB2B",
                 OutputSizeInBits, true);
        }

        [TestMethod]
        public void TestKMAC256XOFNISTSample2()
        {
            DoComputeKMAC256(RawKeyInHex, "", Data,
                "FF7B171F1E8A2B24683EED37830EE797538BA8DC563F6DA1E667391A75EDC02CA633079F81CE12A25F45615EC89972031D18337331D24CEB8F8CA8E6A19FD98B",
                OutputSizeInBits, true);
        }

        [TestMethod]
        public void TestKMAC256XOFNISTSample3()
        {
            DoComputeKMAC256(RawKeyInHex, CustomizationMessage, Data,
                 "D5BE731C954ED7732846BB59DBE3A8E30F83E77A4BFF4459F2F1C2B4ECEBB8CE67BA01C62E8AB8578D2D499BD1BB276768781190020A306A97DE281DCC30305D",
                 OutputSizeInBits, true);
        }

        [TestMethod]
        public void TestXofShouldRaiseExceptionOnWriteAfterRead()
        {
            byte[] LKey = Converters.ConvertHexStringToBytes(RawKeyInHex);
            byte[] LCustomization = Converters.ConvertStringToBytes(CustomizationMessage, Encoding.UTF8);
            byte[] LData = Converters.ConvertHexStringToBytes(TestConstants.ZeroToThreeInHex);

            IXOF Hash = HashFactory.XOF.CreateKMAC256XOF(LKey, LCustomization, OutputSizeInBits) as IXOF;

            Assert.ThrowsException<InvalidOperationHashLibException>(() => CallShouldRaiseException(Hash));
        }
    }
}