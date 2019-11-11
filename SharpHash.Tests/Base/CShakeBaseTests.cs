using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Interfaces;
using SharpHash.Tests;
using SharpHash.Utils;
using System.Text;

namespace SharpHash
{
    public abstract class CShakeBaseTests : XOFBaseTests
    {
        protected static readonly byte[] FS = Converters.ConvertStringToBytes("Email Signature", Encoding.UTF8);

        protected IHash hash { get; set; }
        protected string ExpectedHashOfZeroToThreeInHex { get; set; }
        protected string ExpectedHashOfZeroToOneHundredAndNinetyNineInHex { get; set; }

        [TestMethod]
        public void TestCShakeVectors()
        {
            TestHelper.TestActualAndExpectedData(
                Converters.ConvertHexStringToBytes(TestConstants.ZeroToThreeInHex),
                ExpectedHashOfZeroToThreeInHex, hash);

            TestHelper.TestActualAndExpectedData(
                Converters.ConvertHexStringToBytes(TestConstants.ZeroToOneHundredAndNinetyNineInHex),
                ExpectedHashOfZeroToOneHundredAndNinetyNineInHex, hash);
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

        [TestMethod]
        public void TestHMACCloneIsCorrect()
        {
            TestHelper.TestHMACCloneIsCorrect(hash);
        }
    }
}