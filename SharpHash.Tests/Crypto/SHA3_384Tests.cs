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
    public class SHA3_384Tests : CryptoHashBaseTests
    {
        public SHA3_384Tests()
        {
            hash = HashFactory.Crypto.CreateSHA3_384();

            ExpectedHashOfEmptyData = "0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004";
            ExpectedHashOfDefaultData = "87DD2935CD0DDEFFB8694E70ED1D33EABCEA848BD93A7A7B7227603B7C080A70BCF29FCEED66F456A7FB593EB23F950C";
            ExpectedHashOfOnetoNine = "8B90EDE4D095409F1A12492C2520599683A9478DC70B7566D23B3E41ECE8538C6CDE92382A5E38786490375C54672ABF";
            ExpectedHashOfabcde = "348494236B82EDDA7602C78BA67FC3838E427C63C23E2C9D9AA5EA6354218A3C2CA564679ACABF3AC6BF5378047691C4";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "802D520828C580A61EE4BFA138BE23708C22DB97F94913AF5897E3C9C12BA6C4EC33BFEB79691D2F302315B27674EA40";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "52A4A926B60AA9F6B7DB1C8F5344A097540A8E2115164BF75734907E88C2BC1F7DD84D0EE8569B9857590A39EB5FF499";
        }
    }
}