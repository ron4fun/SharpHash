using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Crypto;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.Linq;
using System.Text;

namespace SharpHash.XOFandKMAC.Tests
{
    [TestClass]
    public class Blake3XOFTests : ShakeBaseTests
    {

        public Blake3XOFTests()
        {
            hash = HashFactory.XOF.CreateBlake3XOF(null, 512);
            VeryLongShake = HashFactory.XOF.CreateBlake3XOF(null, 8000) as IXOF;

            ExpectedHashOfEmptyData = "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262E00F03E7B69AF26B7FAAF09FCD333050338DDFE085B8CC869CA98B206C08243A";
            ExpectedHashOfDefaultData = "BB8DB7E4155BFDB254AD49D8D3105C57B6AC3E783E6D316A75E8B8F8911EB41F800B6ACB7F3593E1787BF62433D016B800B75C14C4E3E395FC5571ADEB1A7143";
            ExpectedHashOfOnetoNine = "B7D65B48420D1033CB2595293263B6F72EABEE20D55E699D0DF1973B3C9DEED15042F0A21EE5D17C59E507AE27E48A7CD85F69DCD816C5F421883F36E513D9FE";
            ExpectedHashOfabcde = "0648C03B5AD9BB6DDF8306EEF6A33EBAE8F89CB4741150C1AE9CD662FDCC1EE2AB9CED8A57741468B7C3163AF41767186CE877C7AE21260064FD4EAD6004D549";
            ExpectedVeryLongShakeOfEmptyString =
                 "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262E00F03E7B69AF26B7FAAF09FCD333050338DDFE085B8CC869CA98B206C08243A26F5"
                + "487789E8F660AFE6C99EF9E0C52B92E7393024A80459CF91F476F9FFDBDA7001C22E159B402631F277CA96F2DEFDF1078282314E763699A31C5363165421CCE14D30F"
                + "8A03E49EE25D2EA3CD48A568957B378A65AF65FC35FB3E9E12B81CA2D82CDEE16C68908A6772F827564336933C89E6908B2F9C7D1811C0EB795CBD5898FE6F5E8AF7633"
                + "19CA863718A59AFF3D99660EF642483E217EF0C8785827284FEA90D42225E3CDD6A179BEE852FD24E7D45B38C27B9C2F9469EA8DBDB893F00E28534C7D15B59BADD5A5BDE"
                + "B090E98EB93C5B2F42101394ACB7C72E9B60094D5442096754600DB8C0FA6DBDFEA154C324C07BF17B7AB0D1488AE5EF76CB7611BAEF17087D84C08B4F950D3D85E00E7001"
                + "813FE029A10722BB003531D5AE406386E78CCA4CA7CACE8A41D294F6EE3B1C645832109B5B19304360B8AB79581E351C518849EAA7C7E14F37BA5B769D2CAF191F9DDEE2D49"
                + "82B6213947A7D047A03F5E456F2588F56E4075C756A319299FBA4001C4B6FB89FBFD93B0739DC684424A439CEFB447D5E191919C4581BC153BD2F2FAE39758F1322AE52EA8B2"
                + "D859887A71F70C03E28765709711950C2C06BF5C7D1BB6C235F722CE6DB047FE97CF74B87ADBD6531CB14A1193A8974F939DD2EB21335793880279905402DBDA8B5EC0A7C82A"
                + "69151BB42F7126E4157A510C6123139815BA3DF3FD1D810795D1F4F49CB8B0D63D8D07833CE95FCFF2B8B8677D1F6C3EE3CF2A00CE72A32E93F5E225A065A0726DC5C9AD5C26F"
                + "2C3560E401BA5079C3D63A8B29175BC9597B09A2BE664E6641F2D2EBFAFE58D5C025EE367396B4C0E31F9D761B779FF27DBAB678CFBB3C62460CC68A4C3187E9788E045EC92437"
                + "1C3027903A42059D1ED659406706C5E4381C931886A034E20689FFA78221E39B42326A9725C5D669D5E2ABAA1C4640AFC7E4D3A5FF5C5513F1B13BF865F4F02EC09453DBD0BCD1D0"
                + "AC3444141CC78B662F00811F095D1A1614EDCB516C70FB3BBF4C9ED58F8FBBDDE8CB1B5497585C53FB33EB7A98810780056C9952848F129D5A87DD36774C1B91E135C1ACEF799E6E4"
                + "320FB862C3619F6874CE0D7550D260308D7E309EEEA5026A534D37DFA4F703BF185C015D99D88A1E350639634D1C7F1DE79FAEBC0DFECAC66089E6F44C916DEBC12965DD0ECFDDF8A"
                + "D4CAFB5ABC45FC9FCA9780C26F457EA9DDCF5370A4D042BC5B9BFA87FAC10F88B170CD22CB9AB2255B251529272BADDF757AD471C4935363495B8E626421859FF304F6D5D527AAE2AF"
                + "7444F3E14C8CD41F9BB1E19A1418E08A5B535C79554";
        }

        [TestMethod]
        public void TestCheckTestVectors()
        {
            Int32 LIdx;
            String LKeyAsString, LCtxAsString;
            string[] LVector = null;
            byte[] LFullInput = null, LChunkedInput = null, LNilKey = null, LKey = null, LOutput = null,
                LOutputClone = null, LKeyedOutput = null, LKeyedOutputClone = null, LCtx = null, LSubKey = null;
            IHash LHash = null, LHashClone = null, LKeyedHash = null, LKeyedHashClone = null;

            LFullInput = new byte[1 << 15];
            for (LIdx = 0; LIdx < LFullInput.Length; LIdx++)
                LFullInput[LIdx] = (byte)(LIdx % 251);

            LKeyAsString = "whats the Elvish word for friend";
            LCtxAsString = "BLAKE3 2019-12-27 16:29:52 test vectors context";

            LKey = Converters.ConvertStringToBytes(LKeyAsString, Encoding.UTF8);
            LNilKey = null;
            LCtx = Converters.ConvertStringToBytes(LCtxAsString, Encoding.UTF8);


            for (LIdx = 0; LIdx < Blake3TestVectors.Blake3_XofTestVectors.Length; LIdx++)
            {
                LVector = Blake3TestVectors.Blake3_XofTestVectors[LIdx];

                LChunkedInput = new byte[Int32.Parse(LVector[0])];
                Utils.Utils.Memcopy(ref LChunkedInput, LFullInput, LChunkedInput.Length);

                LHash = HashFactory.XOF.CreateBlake3XOF(LNilKey, (UInt64)(LVector[1].Length >> 1) * 8);

                LKeyedHash = HashFactory.XOF.CreateBlake3XOF(LKey, (UInt64)(LVector[2].Length >> 1) * 8);

                LHash.Initialize();
                LKeyedHash.Initialize();

                LHash.TransformBytes(LChunkedInput);
                LKeyedHash.TransformBytes(LChunkedInput);
                LOutput = LHash.TransformFinal().GetBytes();
                LKeyedOutput = LKeyedHash.TransformFinal().GetBytes();

                if (!LOutput.SequenceEqual(Converters.ConvertHexStringToBytes(LVector[1])))
                    Assert.Fail(String.Format("BLAKE3XOF mismatch on test vector, Expected \"{0}\" but got \"{1}\"",
                        LVector[1], Converters.ConvertBytesToHexString(LOutput, false)));

                if (!LKeyedOutput.SequenceEqual(Converters.ConvertHexStringToBytes(LVector[2])))
                    Assert.Fail(String.Format("BLAKE3XOF mismatch on keyed test vector, Expected \"{0}\" but got \"{1}\"",
                        LVector[2], Converters.ConvertBytesToHexString(LKeyedOutput, false)));

                LOutput = new byte[LVector[1].Length >> 1];
                LKeyedOutput = new byte[LVector[2].Length >> 1];

                LHash.TransformBytes(LChunkedInput);
                LKeyedHash.TransformBytes(LChunkedInput);
                LHashClone = LHash.Clone();
                LKeyedHashClone = LKeyedHash.Clone();

                (LHash as IXOF).DoOutput(ref LOutput, 0, (UInt64)LOutput.Length);
                (LKeyedHash as IXOF).DoOutput(ref LKeyedOutput, 0, (UInt64)LKeyedOutput.Length);

                if (!LOutput.SequenceEqual(Converters.ConvertHexStringToBytes(LVector[1])))
                    Assert.Fail(String.Format("BLAKE3XOF mismatch on test vector after a reset, Expected \"{0}\" but got \"{1}\"",
                        LVector[1], Converters.ConvertBytesToHexString(LOutput, false)));

                if (!LKeyedOutput.SequenceEqual(Converters.ConvertHexStringToBytes(LVector[2])))
                    Assert.Fail(String.Format("BLAKE3XOF mismatch on keyed test vector after a reset, Expected \"{0}\" but got \"{1}\"",
                        LVector[2], Converters.ConvertBytesToHexString(LKeyedOutput, false)));

                LOutputClone = LHashClone.TransformFinal().GetBytes();
                LKeyedOutputClone = LKeyedHashClone.TransformFinal().GetBytes();

                if (!LOutput.SequenceEqual(LOutputClone))
                    Assert.Fail(String.Format("BLAKE3XOF mismatch on test vector test vector against a clone, Expected \"{0}\" but got \"{1}\"",
                        LVector[1], Converters.ConvertBytesToHexString(LOutputClone, false)));

                if (!LKeyedOutput.SequenceEqual(LKeyedOutputClone))
                    Assert.Fail(String.Format("BLAKE3XOF mismatch on keyed test vector test vector against a clone, Expected \"{0}\" but got \"{1}\"",
                        LVector[2], Converters.ConvertBytesToHexString(LKeyedOutputClone, false)));

                //LSubKey = new byte[LVector[3].Length >> 1];

                //Blake3.DeriveKey(LChunkedInput, LCtx, LSubKey);

                //if (!LSubKey.SequenceEqual(Converters.ConvertHexStringToBytes(LVector[3])))
                //    Assert.Fail(String.Format("Blake3DeriveKey mismatch on test vector, Expected \"{0}\" but got \"{1}\"",
                //        LVector[3], Converters.ConvertBytesToHexString(LSubKey, false)));

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
