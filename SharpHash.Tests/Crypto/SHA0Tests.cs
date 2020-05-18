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

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class SHA0Tests : CryptoHashBaseTests
    {
        public SHA0Tests()
        {
            hash = HashFactory.Crypto.CreateSHA0();

            ExpectedHashOfEmptyData = "F96CEA198AD1DD5617AC084A3D92C6107708C0EF";
            ExpectedHashOfDefaultData = "C9CBBE593DE122CA36B13CC37FE2CA8D5606FEED";
            ExpectedHashOfOnetoNine = "F0360779D2AF6615F306BB534223CF762A92E988";
            ExpectedHashOfabcde = "D624E34951BB800F0ACAE773001DF8CFFE781BA8";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "CDA87167A558311B9154F372F21A453030BBE16A";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "EAA73E85DCAC5BAD0A0E71C0695F901FC32DB38A";
        }
    }
}