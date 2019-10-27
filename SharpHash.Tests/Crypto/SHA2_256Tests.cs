using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA2_256Tests : CryptoHashBaseTests
    {
        static SHA2_256Tests()
        {
            hash = HashFactory.Crypto.CreateSHA2_256();

            ExpectedHashOfEmptyData = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
            ExpectedHashOfDefaultData = "BCF45544CB98DDAB731927F8760F81821489ED04C0792A4D254134887BEA9E38";
            ExpectedHashOfOnetoNine = "15E2B0D3C33891EBB0F1EF609EC419420C20E320CE94C65FBC8C3312448EB225";
            ExpectedHashOfabcde = "36BBE50ED96841D10443BCB670D6554F0A34B761BE67EC9C4A8AD2C0C44CA42C";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "BC05A7D3B13A4A67445C62389564D35B18F33A0C6408EC8DA0CB2506AE6E2D14";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "92678A1C746AAEAA1D3F0C9DAC4BCA73801D278B51C1F6861D49C9A2C1175687";
        }
    }
}