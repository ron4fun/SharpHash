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
    public class RIPEMD160Tests : CryptoHashBaseTests
    {
        public RIPEMD160Tests()
        {
            hash = HashFactory.Crypto.CreateRIPEMD160();

            ExpectedHashOfEmptyData = "9C1185A5C5E9FC54612808977EE8F548B2258D31";
            ExpectedHashOfDefaultData = "0B8EAC9A2EA1E267750CE639D83A84B92631462B";
            ExpectedHashOfOnetoNine = "D3D0379126C1E5E0BA70AD6E5E53FF6AEAB9F4FA";
            ExpectedHashOfabcde = "973398B6E6C6CFA6B5E6A5173F195CE3274BF828";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "4C373970BDB829BE3B6E0B2D9F510E9C35C9B583";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "76D728D9BF39ED42E0C451A9526E3F0D929F067D";
        }
    }
}