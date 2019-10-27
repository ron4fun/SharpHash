using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Crypto.Tests
{
    [TestClass]
    public class Snefru_8_128Tests : CryptoHashBaseTests
    {
        static Snefru_8_128Tests()
        {
            hash = HashFactory.Crypto.CreateSnefru_8_128();

            ExpectedHashOfEmptyData = "8617F366566A011837F4FB4BA5BEDEA2";
            ExpectedHashOfDefaultData = "1EA32485C121D07D1BD22FC4EDCF554F";
            ExpectedHashOfOnetoNine = "486D27B1F5F4A20DEE14CC466EDA9069";
            ExpectedHashOfabcde = "ADD78FA0BEA8F6283FE5D011BE6BCA3B";
            ExpectedHashOfDefaultDataWithHMACWithLongKey = "296DEC851C9F6A6C9E1FD42679CE3FD2";
            ExpectedHashOfDefaultDataWithHMACWithShortKey = "B7D06604FCA943939525BA82BA69706E";
        }
    }
}