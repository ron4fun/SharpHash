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
    public class Keccak_288Tests : CryptoHashBaseTests
    {
        public Keccak_288Tests()
        {
            hash = HashFactory.Crypto.CreateKeccak_288();

            ExpectedHashOfEmptyData = "6753E3380C09E385D0339EB6B050A68F66CFD60A73476E6FD6ADEB72F5EDD7C6F04A5D01";
            ExpectedHashOfDefaultData = "A81F64CA8FAFFA1FC64A8E40E3F6A6FEA3303753B8F7F25E7E6EABA3D99A13F1EDF0F125";
            ExpectedHashOfOnetoNine = "2B87D3D1907AA78236C7037752CA8C456611C24CE8FBAAAC961AABF3137B471C93A8F031";
            ExpectedHashOfabcde = "F996518E4703A5D660B250D720A143B0A44C5DE31819A82FEF0F30158D18E74E6DF405F6";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "EDC893C0E0E9E70F299098D5049D82EE6811582B93B5C38A5DC9FD14F984A352042365D0";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "615143BAA85817D4F6F051E33801A900AEA480E716A01826E1392743A92B46EED587E9F7";
        }
    }
}