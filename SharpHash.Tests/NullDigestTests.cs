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
using SharpHash.Interfaces;
using SharpHash.Utils;
using System.Linq;
using System.Text;

namespace SharpHash.Tests
{
    [TestClass]
    public class NullDigestTests
    {
        protected IHash hash = HashFactory.NullDigestFactory.CreateNullDigest();

        protected string ExpectedHashOfEmptyData = "00000001";
        protected string ExpectedHashOfDefaultData = "25D40524";
        protected string ExpectedHashOfOnetoNine = "091E01DE";
        protected string ExpectedHashOfabcde = "05C801F0";

        [TestMethod]
        public void TestBytesabcde()
        {
            byte[] BytesABCDE, Result;

            BytesABCDE = Converters.ConvertStringToBytes("abcde", Encoding.UTF8);

            hash.Initialize();

            hash.TransformBytes(BytesABCDE);

            Result = hash.TransformFinal().GetBytes();

            Assert.IsTrue(Enumerable.SequenceEqual(BytesABCDE, Result));
        }

        [TestMethod]
        public void TestEmptyBytes()
        {
            byte[] BytesEmpty, Result;

            BytesEmpty = Converters.ConvertStringToBytes("", Encoding.UTF8);

            hash.Initialize();

            hash.TransformBytes(BytesEmpty);

            Result = hash.TransformFinal().GetBytes();

            Assert.IsTrue(Enumerable.SequenceEqual(BytesEmpty, Result));
        }

        [TestMethod]
        public void TestForNullBytes()
        {
            TestHelper.TestForNullBytes(hash);
        }

        [TestMethod]
        public void TestIncrementalHash()
        {
            byte[] BytesZeroToNine, Result, Temp;

            BytesZeroToNine = Converters.ConvertStringToBytes("0123456789", Encoding.UTF8);

            hash.Initialize();

            Temp = new byte[4];
            Utils.Utils.Memcopy(ref Temp, BytesZeroToNine, 4);

            hash.TransformBytes(Temp);

            Temp = new byte[6];
            Utils.Utils.Memcopy(ref Temp, BytesZeroToNine, 6, 4);

            hash.TransformBytes(Temp);

            Result = hash.TransformFinal().GetBytes();

            Assert.IsTrue(Enumerable.SequenceEqual(BytesZeroToNine, Result));

            Assert.ThrowsException<NotImplementedHashLibException>(() => hash.BlockSize);
            Assert.ThrowsException<NotImplementedHashLibException>(() => hash.HashSize);
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
    }
}