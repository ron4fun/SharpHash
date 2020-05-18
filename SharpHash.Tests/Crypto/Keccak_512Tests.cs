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
    public class Keccak_512Tests : CryptoHashBaseTests
    {
        public Keccak_512Tests()
        {
            hash = HashFactory.Crypto.CreateKeccak_512();

            ExpectedHashOfEmptyData = "0EAB42DE4C3CEB9235FC91ACFFE746B29C29A8C366B7C60E4E67C466F36A4304C00FA9CAF9D87976BA469BCBE06713B435F091EF2769FB160CDAB33D3670680E";
            ExpectedHashOfDefaultData = "27E67744299C2229F5008141E410B650BB7D70366B8A60BEAE52F8D6F4A8889D1BAEF53191FF53277FD6CFFE76937CDFAC40EB8EE6F32E3B146C05F961E970A8";
            ExpectedHashOfOnetoNine = "40B787E94778266FB196A73B7A77EDF9DE2EF172451A2B87531324812250DF8F26FCC11E69B35AFDDBE639956C96153E71363F97010BC99405DD2D77B8C41986";
            ExpectedHashOfabcde = "37491BD4BF2A4629D4E35602E09812FA94BFC63BAEE4487075E2B6D73F36D01A7392A1719EDBBB5D1D6FA3BA0D144F18229ABC13B7933A4736D6AAB4A3177F18";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "53D5520C2E31F7EAAE1D95CF04663B18C2144AAF141F2630D6454162B3A890D75D59A9D99096411870FBF7A92A563AEA35AFED836DF652C6DF2AB4D373A754E3";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "6FA826F0AFFE589DFD1665264F5516D076F9FEC585FD4227095B467A50E963D45C1730232549E8DDB590C1518BA310612839BBCCDF34F6A0AD6AC8B91D393BE6";
        }
    }
}