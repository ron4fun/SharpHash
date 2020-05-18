///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019 - 2020  Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/SharpHash>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
/// Also, I will like to thank Udezue Chukwunwike (https://github.com/IzarchTech) for
/// his contributions to the growth and development of this library.
///
////////////////////////////////////////////////////////////////////////

using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Crypto.Blake2BConfigurations;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.Linq;

namespace SharpHash.XOFandKMAC.Tests
{
    [TestClass]
    public class Blake2XBTests : ShakeBaseTests
    {

        public Blake2XBTests()
        {
            hash = HashFactory.XOF.CreateBlake2XB(new Blake2XBConfig(), 512);
            VeryLongShake = HashFactory.XOF.CreateBlake2XB(new Blake2XBConfig(), 8000) as IXOF;

            ExpectedHashOfEmptyData = "C5EF3D8845B9B2BA8EA28E9326C9E46E7A5843AD42BACAF927798BEAF554A43CA0830CCF8BB4A24CE1B1D82BD2DA971AFB2BE73919CC5FFF8E7C6A20F87284FA";
            ExpectedHashOfDefaultData = "9A4C47E816EF6A06F9708B8AE2FEE224F18565CE1F08B848945B73A961BB5E83D79B3A71BE6E324243483C265007A2CD67DE3150C26DC799CE7FC201981AC80A";
            ExpectedHashOfOnetoNine = "3FD021E013DF681EE479A6E3CE7D36E53971946C586147D59EECF1634C31C318F03BBCE3CDB0B1EC5CD4BD4EDF8ED1441A37754899BB3D8850FCA5EBE0639ABB";
            ExpectedHashOfabcde = "81B9FF044391492C89822F8A96279128E876FC5326B0C5C83552B503409F1A6A6CA66DAECE711FE4FCC5DBD92D8560172A64472FAF845CAA7F4297E17ECA1283";
            ExpectedVeryLongShakeOfEmptyString =
                "85DDB224AFA3113F145AC1AA3618BD7496FDC79AF14372734A2CDCE9E8DA30029454BAF1C2D78D528F011B3F3FE824CF05B28C4CF34791B3595AC30AB7B348F" + 
                "23084628A4315036BE75EDCBE93E217B922E7D8E8CD5EBC35580BC2909432E74506C0080718198A87F44BF22B83DE6FCBE6AC98965D9D8B83F37AACB75064FD6205762BA7CDFFF6F4B83" + 
                "672D5296D8D550FDE5B8D16E465D95C26DE2819DA44130EAA3698EC5F2F892133E8F20948523CEE89F01723078FA2E4BE0395638CFAF7F05265C43FF7C08A03EDA0516476CD6C9D14B560E" + 
                "7B1FE6E7D59BD658B434755CC58F1780ADE865EA9D365949BF7D260C46452FFF6CBFA9AB54EED5725E9A4E747F4C8C40F1BBAFCE1EEDDE87476924B78B8F7D61ABC93087327CD3220A" + 
                "088C757B6E5E8C3A2530B08F7710D4E79E7EBA9C1B839A32E941D934D8B675B5029FE5AC6F00E64F5432DB9E40DFFD9C85A28D2D1786C51026F5AFCB06FD58414E12FF94A50D3F583885" + 
                "F5547605C11BF0C3F9CA71AC9EE9B4D5499A92FE4D765F48F9AE48441E65B384B14946F9A639B53CECB91636A9C14246B769FE7A3E6AAFD131110F3ABF157887A18EFFA5CA80887C358F5F" + 
                "7292A09F3AB997D3FD4D08E2178F358F46B8862F220E495940BD60BF96FA219B0B90383E5FBF4DF496E922354DE70363583932F440E839093E3DB3615A3A38A3EF79BEFCA3C8B10FA55" + 
                "FB997E6B25EB68DF7AD4A69FF2B9D20CB3EC981143CEC641732C4FFB899E1496CF8920167097BE4AD3448385FB25C5BE411027798E89ADC79F8225DE42E292C02D24BD2356F9C9D" + 
                "CA502C0A1671BB7D25D91A038A6634670C9E9E668B18124C56CBC3FC7E56A01E8BAF23463DC2ACFEDF572070BD3EAD179CD4008A198EE0A544A975D401A5CED306A861FF23D17D91F67F" + 
                "F2F7CF453F9C444DDFCA81761C482299E098FEA53CD8C809B5E3F5AFEF857BFE918833EBF7B7B272DC014967F5610E39CD09EB8E7AB662F4DFD0CEF98DEC5F95307AA900EF27DF36373FE31" + 
                "6DCB951C623729B26F61723B73AD442250F8C2EC7033447795860232B9012B4C837EA47E0F69A9C4A0489AD7BC48BC58BB8EB948BBAC2A638549EDE38B215ABFC30FBEB29F255A9C710A2" + 
                "29B4070A5B09D894E1460DD577173892779BBA4257B60FCC9253BE3E6350221CE615438A04C86E3D6FAB218DE5947459B93D02D00C771F8F3820BABCAE18ADF599649F7716C7CECE86866B" + 
                "E1B03FC5390199A7607CA7E45CDAD99411A850125C90AD526C2008293185C1B5B008A458F8F885C8614F317ED52DBAF3E82D0A4B0E47E41C63F145FB17B994B5E9829D8138876A3ADA" + 
                "872FD00914654D504245150B178B919D9F9A7219DB86595D3AACA009798FB52DD0D28F8FFBE4D75063EFD98E655CDEE16";

        }

        [TestMethod]
        public void TestCheckTestVectors()
        {
            Int32 i;
            string[] vector = null;
            byte[] Input, Key, outBytes, outClone;
            IHash h, Clone;


            for (i = 0; i < Blake2BTestVectors.Blake2XB_XofTestVectors.Length; i++)
            {
                vector = Blake2BTestVectors.Blake2XB_XofTestVectors[i];
                Input = Converters.ConvertHexStringToBytes(Blake2BTestVectors.Blake2XB_XofTestInput);
                Key = Converters.ConvertHexStringToBytes(vector[0]);

                h = HashFactory.XOF.CreateBlake2XB(Key, (UInt32)(vector[1].Length >> 1) * 8);
                h.Initialize();
                h.TransformBytes(Input);
                outBytes = h.TransformFinal().GetBytes();

                if (!outBytes.SequenceEqual(Converters.ConvertHexStringToBytes(vector[1])))
                {
                    Assert.Fail(String.Format("BLAKE2XB mismatch on test vector, Expected \"{0}\" but got \"{1}\"",
                        vector[1], Converters.ConvertBytesToHexString(outBytes, false)));
                }

                Array.Resize(ref outBytes, vector[1].Length >> 1);

                h.TransformBytes(Input);
                Clone = h.Clone();

                (h as IXOF).DoOutput(ref outBytes, 0, (UInt32)outBytes.Length);
                if (!outBytes.SequenceEqual(Converters.ConvertHexStringToBytes(vector[1])))
                {
                    Assert.Fail(String.Format("BLAKE2XB mismatch on test vector after a reset, Expected \"{0}\" but got \"{1}\"",
                        vector[1], Converters.ConvertBytesToHexString(outBytes, false)));
                }

                outClone = Clone.TransformFinal().GetBytes();

                if (!outBytes.SequenceEqual(outClone))
                {
                    Assert.Fail(String.Format("BLAKE2XB mismatch on test vector test vector against a clone, Expected \"{0}\" but got \"{1}\"",
                        vector[1], Converters.ConvertBytesToHexString(outClone, false)));
                }
            }
        }

        [TestMethod]
        public void TestXofShouldRaiseExceptionOnWriteAfterRead()
        {
            IXOF Hash = hash as IXOF;
            Assert.ThrowsException<InvalidOperationHashLibException>(() => CallShouldRaiseException(Hash));
        }
    }

}
