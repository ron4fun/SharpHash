using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class RIPEMDTests : CryptoHashBaseTests
    {
        static RIPEMDTests()
        {
            hash = HashFactory.Crypto.CreateRIPEMD();

            ExpectedHashOfEmptyData = "9F73AA9B372A9DACFB86A6108852E2D9";
            ExpectedHashOfDefaultData = "B3F629A9786744AA105A2C150869C236";
            ExpectedHashOfOnetoNine = "C905B44C6429AD0A1934550037D4816F";
            ExpectedHashOfabcde = "68D2362617E85CF1BF7381DF14045DBB";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "B06D09CE5452ADEEADF468E00DAC5C8B";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "219ACFCF07BDB775FBA73DACE1E97E08";
        }
    }
}