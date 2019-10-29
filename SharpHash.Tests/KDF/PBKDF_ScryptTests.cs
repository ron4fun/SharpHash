using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.Text;

namespace SharpHash.KDF.Tests
{
    /// <summary>
    /// scrypt test vectors from "Stronger Key Derivation Via Sequential Memory-hard Functions" Appendix B.
    /// (http://www.tarsnap.com/scrypt/scrypt.pdf)
    /// </summary>
    [TestClass]
    public class PBKDF_ScryptTestCase
    {
        private string ActualString { get; set; }
        private string ExpectedString { get; set; }

        private string DoTestVector(string a_Password, string a_Salt, Int32 a_Cost, Int32 a_BlockSize,
            Int32 a_Parallelism, Int32 a_OutputSize)
        {
            IPBKDF_Scrypt PBKDF_Scrypt;
            byte[] PasswordBytes, SaltBytes, OutputBytes;

            PasswordBytes = Converters.ConvertStringToBytes(a_Password, Encoding.ASCII);
            SaltBytes = Converters.ConvertStringToBytes(a_Salt, Encoding.ASCII);

            PBKDF_Scrypt = HashFactory.KDF.PBKDF_Scrypt.CreatePBKDF_Scrypt(PasswordBytes,
                SaltBytes, a_Cost, a_BlockSize, a_Parallelism);
            OutputBytes = PBKDF_Scrypt.GetBytes(a_OutputSize);
            PBKDF_Scrypt.Clear();

            return Converters.ConvertBytesToHexString(OutputBytes, false);
        } //

        private void DoCheckOk(string a_Msg, byte[] a_Password, byte[] a_Salt, Int32 a_Cost,
            Int32 a_BlockSize, Int32 a_Parallelism, Int32 a_OutputSize)
        {
            IPBKDF_Scrypt PBKDF_Scrypt = null;

            try
            {
                try
                {
                    PBKDF_Scrypt = HashFactory.KDF.PBKDF_Scrypt.CreatePBKDF_Scrypt(a_Password,
                        a_Salt, a_Cost, a_BlockSize, a_Parallelism);
                    PBKDF_Scrypt.GetBytes(a_OutputSize);
                } //
                catch (ArgumentHashLibException)
                {
                    Assert.Fail(a_Msg);
                } //
                catch (Exception)
                {
                    Assert.Fail(a_Msg);
                } //
            }
            finally
            {
                PBKDF_Scrypt?.Clear();
            } //
        } //

        private void DoCheckIllegal(string a_Msg, byte[] a_Password, byte[] a_Salt,
            Int32 a_Cost, Int32 a_BlockSize, Int32 a_Parallelism, Int32 a_OutputSize)
        {
            try
            {
                HashFactory.KDF.PBKDF_Scrypt.CreatePBKDF_Scrypt(a_Password, a_Salt, a_Cost,
                    a_BlockSize, a_Parallelism).GetBytes(a_OutputSize);

                Assert.Fail(a_Msg);
            }
            catch (ArgumentHashLibException)
            {
                // pass so we do nothing
            }
            catch (Exception)
            {
                // pass so we do nothing
            } //
        } //

        [TestMethod]
        public void TestParameters()
        {
            DoCheckOk("Minimal values", null, null, 2, 1, 1, 1);
            DoCheckIllegal("Cost parameter must be > 1", null, null, 1, 1, 1, 1);
            DoCheckOk("Cost parameter 32768 OK for r = 1", null, null, 32768, 1, 1, 1);
            DoCheckIllegal("Cost parameter must < 65536 for r = 1", null, null,
              65536, 1, 1, 1);
            DoCheckIllegal("Block size must be >= 1", null, null, 2, 0, 2, 1);
            DoCheckIllegal("Parallelisation parameter must be >= 1", null, null, 2,
              1, 0, 1);
            // disabled test because it"s very expensive
            // DoCheckOk("Parallelisation parameter 65535 OK for r = 4", null, null, 2, 32,
            // 65535, 1);
            DoCheckIllegal("Parallelisation parameter must be < 65535 for r = 4", null,
              null, 2, 32, 65536, 1);

            DoCheckIllegal("Len parameter must be > 1", null, null, 2, 1, 1, 0);
        }

        [TestMethod]
        public void TestVectors()
        {
            ActualString = DoTestVector("", "", 16, 1, 1, 64);
            ExpectedString = "77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906";

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.", ExpectedString, ActualString));

            ActualString = DoTestVector("password", "NaCl", 1024, 8, 16, 64);
            ExpectedString = "FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640";

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.", ExpectedString, ActualString));

            ActualString = DoTestVector("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64);
            ExpectedString = "7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887";

            Assert.AreEqual(ExpectedString, ActualString,
                String.Format("Expected {0} but got {1}.", ExpectedString, ActualString));

            // disabled test because it"s very expensive
            // ActualString  = DoTestVector("pleaseletmein", "SodiumChloride", 1048576,
            // 8, 1, 64);
            // ExpectedString  =
            // "2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA478E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4";
            //
            // Assert.AreEqual(ExpectedString, ActualString, String.Format("Expected %s but got %s.",
            // [ExpectedString, ActualString]));
        } //
    } //
}