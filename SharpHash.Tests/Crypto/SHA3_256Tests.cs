using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA3_256Tests : CryptoHashBaseTests
    {
        public SHA3_256Tests()
        {
            hash = HashFactory.Crypto.CreateSHA3_256();

            ExpectedHashOfEmptyData = "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A";
            ExpectedHashOfDefaultData = "C334674D808EBB8B7C2926F043D1CAE78D168A05B70B9210C9167EA6DC300CE2";
            ExpectedHashOfOnetoNine = "87CD084D190E436F147322B90E7384F6A8E0676C99D21EF519EA718E51D45F9C";
            ExpectedHashOfabcde = "D716EC61E18904A8F58679B71CB065D4D5DB72E0E0C3F155A4FEFF7ADD0E58EB";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "B8EC49AF4DE71CB0561A9F0DF7B156CC7784AC044F12B65048CE6DBB27A57E66";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "1019B70021A038345192F00D02E33FA4AF8949E80AD592C4671A438DCCBCFBDF";
        }
    }
}