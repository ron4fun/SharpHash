using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Haval_3_128Tests : CryptoHashBaseTests
    {
        public Haval_3_128Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_3_128();

            ExpectedHashOfEmptyData = "C68F39913F901F3DDF44C707357A7D70";
            ExpectedHashOfDefaultData = "04AF7562BA75D5767ADE2A71E4BE33DE";
            ExpectedHashOfOnetoNine = "F2F92D4E5CA6B92A5B5FC5AC822C39D2";
            ExpectedHashOfabcde = "51D4032478AA59182916E6C111FA79A6";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "E5639CDBE9AE8B58DEC50065909624D4";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "9D49ED7B5D42C64F590A164C5D1AAE9F";
        }
    }

    [TestClass]
    public class Haval_4_128Tests : CryptoHashBaseTests
    {
        public Haval_4_128Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_4_128();

            ExpectedHashOfEmptyData = "EE6BBF4D6A46A679B3A856C88538BB98";
            ExpectedHashOfDefaultData = "C815192C498CF266D0EB32E90D60892E";
            ExpectedHashOfOnetoNine = "52DFE2F3DA02591061B02DBDC1510F1C";
            ExpectedHashOfabcde = "61634059D9B8336FEB32CA27533ED284";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "37A443E8FB7DE00C28BCE8D3F47BECE8";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "9A0B60DEB9F9FBB2A9DAD87A8C653E72";
        }
    }

    [TestClass]
    public class Haval_5_128Tests : CryptoHashBaseTests
    {
        public Haval_5_128Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_5_128();

            ExpectedHashOfEmptyData = "184B8482A0C050DCA54B59C7F05BF5DD";
            ExpectedHashOfDefaultData = "B335D2DC38EFB9D937B803F7581AF88D";
            ExpectedHashOfOnetoNine = "8AA1C1CA3A7E4F983654C4F689DE6F8D";
            ExpectedHashOfabcde = "11C0532F713332D45D6769376DD6EB3B";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "AB287584D5D67B006986F039321FBA2F";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "1D5D93E71FF0B324C54ADD1FBDE1F4E4";
        }
    }

    [TestClass]
    public class Haval_3_160Tests : CryptoHashBaseTests
    {
        public Haval_3_160Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_3_160();

            ExpectedHashOfEmptyData = "D353C3AE22A25401D257643836D7231A9A95F953";
            ExpectedHashOfDefaultData = "4A5E28CA30029D2D04287E6C807E74D297A7FC74";
            ExpectedHashOfOnetoNine = "39A83AF3293CDAC04DE1DF3D0BE7A1F9D8AAB923";
            ExpectedHashOfabcde = "8D7C2218BDD8CB0608BA2479751B44BB15F1FC1F";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "B42F2273A6220C65B5ADAE1A9A1188B9D4398D2A";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "E686A2E785EA222FA28911D9243567EB72362D3C";
        }
    }

    [TestClass]
    public class Haval_4_160Tests : CryptoHashBaseTests
    {
        public Haval_4_160Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_4_160();

            ExpectedHashOfEmptyData = "1D33AAE1BE4146DBAACA0B6E70D7A11F10801525";
            ExpectedHashOfDefaultData = "9E86A9E2D964CCF9019593C88F40AA5C725E0912";
            ExpectedHashOfOnetoNine = "B03439BE6F2A3EBED93AC86846D029D76F62FD99";
            ExpectedHashOfabcde = "F74B326FE2CE8F5BA151B85B16E67B28FE71F131";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "E7969DB764172896F2467CF74F62BBE231E2772D";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "6FEAC0105DA74AEDC8FA76A1CF0848C8CA94BA28";
        }
    }

    [TestClass]
    public class Haval_5_160Tests : CryptoHashBaseTests
    {
        public Haval_5_160Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_5_160();

            ExpectedHashOfEmptyData = "255158CFC1EED1A7BE7C55DDD64D9790415B933B";
            ExpectedHashOfDefaultData = "A9AB9AB152BB4413B717228C3A65E75644542A35";
            ExpectedHashOfOnetoNine = "11F592B3A1A1A9C0F9C638C33B69E442D06C1D99";
            ExpectedHashOfabcde = "53734616DD6761E2A1D2BD520035287972625385";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "EF034569FB10312F89F3FC09DDD9AA5C783A7E21";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "A0FFFE2DE177281E64C5D0A9DC81BFFDF14F6031";
        }
    }

    [TestClass]
    public class Haval_3_192Tests : CryptoHashBaseTests
    {
        public Haval_3_192Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_3_192();

            ExpectedHashOfEmptyData = "E9C48D7903EAF2A91C5B350151EFCB175C0FC82DE2289A4E";
            ExpectedHashOfDefaultData = "4235822851EB1B63D6B1DB56CF18EBD28E0BC2327416D5D1";
            ExpectedHashOfOnetoNine = "6B92F078E73AF2E0F9F049FAA5016D32173A3D62D2F08554";
            ExpectedHashOfabcde = "4A106D88931B60DF1BA352782141C473E79019022D65D7A5";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "AE216E5FA60AE76305DA19EE908FA0531FFE52BCC6A2AB5F";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "3E72C9200EAA6ED8D2EF60B8773BAF147A94E98A1FF4E70B";
        }
    }

    [TestClass]
    public class Haval_4_192Tests : CryptoHashBaseTests
    {
        public Haval_4_192Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_4_192();

            ExpectedHashOfEmptyData = "4A8372945AFA55C7DEAD800311272523CA19D42EA47B72DA";
            ExpectedHashOfDefaultData = "54D4FD0DE4228D55F826B627A128A765378B1DC1F8E6CD75";
            ExpectedHashOfOnetoNine = "A5C285EAD0FF2F47C15C27B991C4A3A5007BA57137B18D07";
            ExpectedHashOfabcde = "88A58D9011CA363A3F3CD113FFEAA44870C07CC14E94FB1B";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "F5C16DFD598655201E6C636B363484FFAED4CCA27F3366A1";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "8AB3C2ED5E17CC15EE9D0740185BFFC53C054BC71B9A44AA";
        }
    }

    [TestClass]
    public class Haval_5_192Tests : CryptoHashBaseTests
    {
        public Haval_5_192Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_5_192();

            ExpectedHashOfEmptyData = "4839D0626F95935E17EE2FC4509387BBE2CC46CB382FFE85";
            ExpectedHashOfDefaultData = "ED197F026B20DB6362CBC62BDD28E0B34F1E287966D84E3B";
            ExpectedHashOfOnetoNine = "EC32312AA79775539675C9BA83D079FFC7EA498FA6173A46";
            ExpectedHashOfabcde = "CDDF16E273A09E9E2F1D7D4761C2D35E1DD6EE327F1F5AFD";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "C28A804383403F608CB4A6473BCAF744CF25E62AF28C5934";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "AB2C407C403A82EEADF2A0B3F4B66B34A12322159E7A95B6";
        }
    }

    [TestClass]
    public class Haval_3_224Tests : CryptoHashBaseTests
    {
        public Haval_3_224Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_3_224();

            ExpectedHashOfEmptyData = "C5AAE9D47BFFCAAF84A8C6E7CCACD60A0DD1932BE7B1A192B9214B6D";
            ExpectedHashOfDefaultData = "12B7BFA1D36D0163E876A1474EB33CF5BC24C1BBBB181F28ACEE8D36";
            ExpectedHashOfOnetoNine = "28E8CC65356B43ACBED4DD70F11D0827F17C4442D323AAA0A0DE285F";
            ExpectedHashOfabcde = "177DA8770D5BF50E1B5D82DD60DF2635102D490D86F876E70F7A4080";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "64F21A46C5B17F4AAD8C28F970428BAA00C4096132369A7E5C0B2F67";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "2C403CCE41533900919919CA9B8A637AEC0A1E1F7FA154F978592B6B";
        }
    }

    [TestClass]
    public class Haval_4_224Tests : CryptoHashBaseTests
    {
        public Haval_4_224Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_4_224();

            ExpectedHashOfEmptyData = "3E56243275B3B81561750550E36FCD676AD2F5DD9E15F2E89E6ED78E";
            ExpectedHashOfDefaultData = "DA7AB9D08D42C1819C04C7064891DB700DD05C960C3192CB615758B0";
            ExpectedHashOfOnetoNine = "9A08D0CF1D52BB1AC22F6421CFB902E700C4C496B3E990F4606F577D";
            ExpectedHashOfabcde = "3EEF5DC9C3B3DE0F142DB08B89C21A1FDB1C64D7B169425DBA161190";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "462C126C107ADA83089EB66168831EB6804BA6062EC8D049B9B47D2B";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "334328027BA2D8F218F8BF374853252D3150FA774D0CBD6F674AEFE0";
        }
    }

    [TestClass]
    public class Haval_5_224Tests : CryptoHashBaseTests
    {
        public Haval_5_224Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_5_224();

            ExpectedHashOfEmptyData = "4A0513C032754F5582A758D35917AC9ADF3854219B39E3AC77D1837E";
            ExpectedHashOfDefaultData = "D5FEA825ED7B8CBF23938425BAFDBEE9AD127A685EFCA4559BD54892";
            ExpectedHashOfOnetoNine = "2EAADFB8007D9A4D8D7F21182C2913D569F801B44D0920D4CE8A01F0";
            ExpectedHashOfabcde = "D8CBE8D06DC58095EC0E69F1C1A4D4A90893AAE80401779CEB6646A9";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "1DD7A2CF3F32F5C447F50D5A3F6B9C421B243E310C3C292581F95447";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "12B6415C63F4BBA34F0ADD23EEB74AC7EE8A07420D652BF619B9E9D1";
        }
    }

    [TestClass]
    public class Haval_3_256Tests : CryptoHashBaseTests
    {
        public Haval_3_256Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_3_256();

            ExpectedHashOfEmptyData = "4F6938531F0BC8991F62DA7BBD6F7DE3FAD44562B8C6F4EBF146D5B4E46F7C17";
            ExpectedHashOfDefaultData = "9AA25FF9D7559F108E01014C27EBEEA34E8D82BD1A6105D28A53791B74C4C024";
            ExpectedHashOfOnetoNine = "63E8D0AEEC87738F1E820294CBDF7961CD2246B3620B4BAC81BE0B9827D612C7";
            ExpectedHashOfabcde = "3913AB70F6219EEFE10B202DE5991EFDBC4A808203BD60BBFBFC043383AE8F90";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "A587C118D2A575F91A7D3986F0893A32F8DBE13218D4B3CDB93DD0B7566E5003";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "7E24B475617096B102F0F64572E297144B35683476D1768CB35C0E0A43A6BF8F";
        }
    }

    [TestClass]
    public class Haval_4_256Tests : CryptoHashBaseTests
    {
        public Haval_4_256Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_4_256();

            ExpectedHashOfEmptyData = "C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B";
            ExpectedHashOfDefaultData = "B5E97F406CBD4C36CC549072713E733EE31A5F9F23DD6C5982D3A239A9B38434";
            ExpectedHashOfOnetoNine = "DDC95DF473DD169456484BEB4B04EDCA83A5572D9D7ECCD00092365AE4EF8D79";
            ExpectedHashOfabcde = "8F9B46785E52C6C48A0178EDC66D3C23C220D15E52C3C8A13E1CD45D21369193";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "ED5D88C730ED3EB103DDE96AD42DA60825A9B8B0D8BD2ED580EBF92B851B12E7";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "FD0122B375A581D3F06DB6EB992F9A3F46657091E427BB8BD247D835CC086437";
        }
    }

    [TestClass]
    public class Haval_5_256Tests : CryptoHashBaseTests
    {
        public Haval_5_256Tests()
        {
            hash = HashFactory.Crypto.CreateHaval_5_256();

            ExpectedHashOfEmptyData = "BE417BB4DD5CFB76C7126F4F8EEB1553A449039307B1A3CD451DBFDC0FBBE330";
            ExpectedHashOfDefaultData = "E5061D6F4F8645262C5C923F8E607CD77D69CE772E3DE559132B460309BFB516";
            ExpectedHashOfOnetoNine = "77FD61460DB5F89DEFC9A9296FAB68A1730EA6C9C0037A9793DAC8492C0A953C";
            ExpectedHashOfabcde = "C464C9A669D5B43E4C34808114DCE4ECC732D1B71407E7F05468D0B15BFF7E30";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "267B5C9F0A093726E47541C8F1DEADD400AD9AEE0145A59FBD5A18BA2877101E";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "C702F985817A2596D7E0BB073D71DFEF72D77BD45599DD4F7E5D83A8EAF7268B";
        }
    }
}