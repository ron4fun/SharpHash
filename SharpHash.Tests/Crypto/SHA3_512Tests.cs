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
    public class SHA3_512Tests : CryptoHashBaseTests
    {
        public SHA3_512Tests()
        {
            hash = HashFactory.Crypto.CreateSHA3_512();

            ExpectedHashOfEmptyData = "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26";
            ExpectedHashOfDefaultData = "FAA213B928B942C521FD2A4B5F918C9AB6479A1DD122B9485440E56E729976D57C5E7C62F65D8453DCAAADA6B79743DB939F22773FD44C9ECD54B4B7FAFDAE33";
            ExpectedHashOfOnetoNine = "E1E44D20556E97A180B6DD3ED7AE5C465CAFD553FA8747DCA038FB95635B77A37318F7DDF7AEC1F6C3C14BB160BA2497007DECF38DD361CAB199E3B8C8FE1F5C";
            ExpectedHashOfabcde = "1D7C3AA6EE17DA5F4AEB78BE968AA38476DBEE54842E1AE2856F4C9A5CD04D45DC75C2902182B07C130ED582D476995B502B8777CCF69F60574471600386639B";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "ADD449377F25EC360F87B04AE6334D5D7CA90EAF3568D4EBDA3A977B820271952D7D93A7804E29B9791DC19FF7B523E6CCABED180B0B035CCDDA38A7E92DC7E0";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "439C673B33F0F6D9273124782611EA96F1BB62F90672551310C1230ADAAD0D40F63C6D2B17DAFECEFD9CE8848576001D9D68FAD1B9E7DDC146F00CEBE5AFED27";
        }
    }
}