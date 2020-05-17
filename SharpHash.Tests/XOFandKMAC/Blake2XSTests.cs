using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Crypto.Blake2SConfigurations;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.Linq;

namespace SharpHash.XOFandKMAC.Tests
{
    [TestClass]
    public class Blake2XSTests : ShakeBaseTests
    {
        
        public Blake2XSTests()
        {
            hash = HashFactory.XOF.CreateBlake2XS(new Blake2XSConfig(), 256);
            VeryLongShake = HashFactory.XOF.CreateBlake2XS(new Blake2XSConfig(), 8000) as IXOF;

            ExpectedHashOfEmptyData = "F4B358457E5563FB54DF3060AEC26EA3AA1C959CF89F55A22538117ECF708BFC";
            ExpectedHashOfDefaultData = "5ADFC3100CED2EDF93D530E747544B1FF88981E2C8BF4BCA95C434FAEA991718";
            ExpectedHashOfOnetoNine = "EA2BBB210CCC659A88EEE6D07900D719E26D801CC6A5E6214214EBA376FF28A5";
            ExpectedHashOfabcde = "3B42907077820444C727CF6B1FD6CC5E9BF8AA5489F57010670D4045AC0A1466";
            ExpectedVeryLongShakeOfEmptyString =
                 "217B64B104155F7158277FC5B0AFB954138C93A6F1269DC4C642A781BA20EB24B3B4B5C7E6C13645DD584D851BD4280B24E1DBA29C512D3CBD6A5C84A708C1D536A6654DDD1D8E3"
                + "885F0B520092E264C73BD11F8788F2841D9B5004CD643F3E39F4188A20A0E0F639E61B45759C68A7DA76CD657F71EB35E1CBC01D16B6DA21CE30CB6E9328451DB8B3F47323CDB0EBBB1BFA"
                + "F1D038D8F6721B8A6268CE955FD58A08F2F38F18B6E51E4E787BC171C737CED8988D912F91A89FD8DB0F3BEC0BA9117E05A916350067A2AC55ED14D7B51A77C9D5B368D58871A6687424CC2C"
                + "A92FC2F8FD6B1830548B8EC2B10E402F14DF43AAB9F93D73CDE95B14E667D2F00928192651D0681A4C8D9AF7951656162230792D49526E59AE204984E45E3D08F439C04B711E06AC4EB073AD18D95"
                + "8E1D853AA463D05646C98C37941CA909C6E6040983120DEE9EB99D03EBD6766D20909481979897B20E34AF07A2EA96637E9F8E9AAFB6A813360C392710D2A408FB6C5F24980ACCB106468"
                + "61B111BD5716DDAF96F3740BD6D10645DE8632C44643939D9C3CA8795F145DA32A61A7903EEFA12040A4AC9AC237C3DCD8BE742B384E1E60B37F8F471A7E9122498E48236783DAD631120C8E"
                + "A8274F07592FBFF612227EBDB550E954BBA0E8BE25562C7344E5C124FCD96F6F272EF8092BC926735C812873228FE063C8F7B9C54CA7A401AF98A7CA8820D7055BA3B82B8F286B67B415F469"
                + "D4A847ADA022AD05FCB75A27BFA3426225DD2C6D62A77EFD8B2A61AE7726876A658EF872B44625D42EA6005BF2207A33D210083B43555F16C60BE798F54080510B9EF53E181C3EA"
                + "FA675818A5255A8E963B22170EA2C42AF9534AF29FC58DA8289F5BEB1B2F5CBA50DE3D9E3F2AA34A992B7634B780F8D8367274EECF4ACE2FDE88B92CCA35064521BA335C375C4F285F2537FF34"
                + "53F1E1F00D4CFDD91F5F349774DA1BC2D30D7BC0FC84CC087F056FB2425C00C5BD4B79BD048FE79048603961D8910F00EBA4200AF31FD77A9F6D5C051BE29A9555D829F236C425BB65531B"
                + "13E4ED3C7F4EEE77014AE46D1E99D32087AA0B4A984A4DEF9A258376F985820BBF97E5A2702F56EC3FD353F552042CDC9D09502393C2DD702CB434AADD632BB8C562010950C865CC890002"
                + "6D1A7414FD402F5092C7787E7A74238F866EBB623A5DF76B2A5BF916328B6C612CE53694263C7DEFFC8B3245771C22C585C3FFA9932875A439CF2E2ECE68CD24DFDB2CC40813F348411AF7026F662AFCEE1"
                + "3EB53418FB69257FF807691FA896E6486D54FD991E927C492D15C0C9B01D905FAD6FFA294C484DFA6B74400CBDD414A85D458DBFFC366C2AFACCEC7E4EA8D7AB75F52FAAD995ED9CB45D"
                + "C69A8D906E1C09A60DEF1447A3D724F54CCE6";
        }

        [TestMethod]
        public void TestCheckTestVectors()
        {
            Int32 i;
            string[] vector = null;
            byte[] Input, Key, outBytes, outClone;
            IHash h, Clone;


            for (i = 0; i < Blake2STestVectors.Blake2XS_XofTestVectors.Length; i++)
            {
                vector = Blake2STestVectors.Blake2XS_XofTestVectors[i];
                Input = Converters.ConvertHexStringToBytes(Blake2STestVectors.Blake2XS_XofTestInput);
                Key = Converters.ConvertHexStringToBytes(vector[0]);

                h = HashFactory.XOF.CreateBlake2XS(Key, (UInt32)(vector[1].Length >> 1) * 8);
                h.Initialize();
                h.TransformBytes(Input);
                outBytes = h.TransformFinal().GetBytes();

                if (!outBytes.SequenceEqual(Converters.ConvertHexStringToBytes(vector[1])))
                {
                    Assert.Fail(String.Format("BLAKE2XS mismatch on test vector, Expected \"{0}\" but got \"{1}\"",
                        vector[1], Converters.ConvertBytesToHexString(outBytes, false)));
                }

                Array.Resize(ref outBytes, vector[1].Length >> 1);

                h.TransformBytes(Input);
                Clone = h.Clone();

                (h as IXOF).DoOutput(ref outBytes, 0, (UInt32)outBytes.Length);
                if (!outBytes.SequenceEqual(Converters.ConvertHexStringToBytes(vector[1])))
                {
                    Assert.Fail(String.Format("BLAKE2XS mismatch on test vector after a reset, Expected \"{0}\" but got \"{1}\"",
                        vector[1], Converters.ConvertBytesToHexString(outBytes, false)));
                }

                outClone = Clone.TransformFinal().GetBytes();

                if (!outBytes.SequenceEqual(outClone))
                {
                    Assert.Fail(String.Format("BLAKE2XS mismatch on test vector test vector against a clone, Expected \"{0}\" but got \"{1}\"",
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
