﻿///////////////////////////////////////////////////////////////////////
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

namespace SharpHash
{
    public abstract class Blake2SPTestVectors
    {
        public static readonly string[] UnkeyedBlake2SP = null;

        public static readonly string[] KeyedBlake2SP = new string[] {
            "715CB13895AEB678F6124160BFF21465B30F4F6874193FC851B4621043F09CC6",
            "40578FFA52BF51AE1866F4284D3A157FC1BCD36AC13CBDCB0377E4D0CD0B6603",
            "67E3097545BAD7E852D74D4EB548ECA7C219C202A7D088DB0EFEAC0EAC304249",
            "8DBCC0589A3D17296A7A58E2F1EFF0E2AA4210B58D1F88B86D7BA5F29DD3B583",
            "A9A9652C8C677594C87212D89D5A75FB31EF4F47C6582CDE5F1EF66BD494533A",
            "05A7180E595054739948C5E338C95FE0B7FC61AC58A73574745633BBC1F77031",
            "814DE83153B8D75DFADE29FD39AC72DD09CA0F9BC8B7AB6A06BAEE7DD0F9F083",
            "DFD419449129FF604F0A148B4C7D68F1174F7D0F8C8D2CE77F448FD3419C6FB0",
            "B9ED22E7DD8DD14EE8C95B20E7632E8553A268D9FF8633ED3C21D1B8C9A70BE1",
            "95F031671A4E3C54441CEE9DBEF4B7ACA44618A3A333AD7406D197AC5BA0791A",
            "E2925B9D5CA0FF6288C5EA1AF2D22B0A6B79E2DAE08BFD36C3BE10BB8D71D839",
            "16249C744E4951451D4C894FB59A3ECB3FBFB7A45F96F85D1580AC0B842D96DA",
            "432BC91C52ACEB9DAED8832881648650C1B81D117ABD68E08451508A63BE0081",
            "CDE8202BCFA3F3E95D79BACC165D52700EF71D874A3C637E634F644473720D6B",
            "1621621F5C3EE446899D3C8AAE4917B1E6DB4A0ED042315FB2C174825E0A1819",
            "336E8EBC71E2095C27F864A3121EFD0FAA7A41285725A592F61BEDED9DDE86ED",
            "079BE0410E789B36EE7F55C19FAAC691656EB0521F42949B84EE29FE2A0E7F36",
            "17270C4F3488082D9FF9937EAB3CA99C97C5B4596147372DD4E98ACF13DB2810",
            "183C38754D0341CE07C17A6CB6C2FD8BBCC1404FDD014199C78BE1A97559A928",
            "6E52D728A405A6E1F87587BBC2AC91C5C09B2D828AC81E5C4A81D03DD4AA8D5C",
            "F4E08E059B74144BF948146D14A2C81E46DC15FF26EB52344CDD474ABEA14BC0",
            "0F2E0A100ED8A11785962AD4596AF955E30B9AEF930A248DA9322B702D4B6872",
            "5190FCC732F404AAD4364AC7960CFD5B4E348629C372EEB325B5C6C7CBCE59AB",
            "C0C4CB86EA25EA957EEC5B22D2550A1649E6DFFA316BB8F4C91B8FF7A24B2531",
            "2C9EDA135A30AECAF3ACB3D23A3035FBABBA98333165D87FCBF8FE10336ECF20",
            "3CD669E8D56262A2371367224DAE6D759EE152C31533B263FA2E64920877B2A7",
            "18A9A0C2D0EA6C3BB332830F8918B0684F5D3994DF4867462DD06EF0862424CC",
            "7390EA4104A9F4EEA90F81E26A129DCF9F4AF38352D9CB6A812CC8056909050E",
            "E49E0114C629B494B11EA98ECD4032731F153B4650ACACD7E0F6E7DE3DF01977",
            "27C5702BE104B3A94FC43423AEEE83AC3CA73B7F87839A6B2E29607903B7F287",
            "81D2E12EB2F42760C6E3BAA78F84073AE6F5616070FE25BEDE7C7C8248AB1FBA",
            "FAB235D59348AB8CE49BEC77C0F19328FD045DFD608A530336DF4F94E172A5C8",
            "8AAA8D805C58881FF379FBD42C6BF6F14C6C73DF8071B3B228981109CCC015F9",
            "91FDD262203916394740952BCE72B64BABB6F721344DEE8250BF0E46F1BA188F",
            "F7E57B8F85F47D5903AD4CCB8AF62A3E858AAB2B8CC226494F7B00BEDBF5B0D0",
            "F76F21ADDAE96A9646FC06F9BF52AE0848F18C3526B129E15B2C355E2E79E5DA",
            "8AEB1C795F3490015EF4CD61A2807B230EFDC8460173DAD026A4A0FCC2FBF22A",
            "C564FFC623077765BB9787585654CE745DBD108CEF248AB00AD1A2647D990387",
            "FE8942A3E5F5E8CD705104F88210726E53DD7EB3F9A202BF9314B3B9065EB712",
            "DC295359D436EEA78084E7B077FE09B19C5BF3D2A796DAB019E4200599FD8202",
            "70B3F72F749032E25E383B964378EA1C543E9C15DE3A27D86D2A9D2231EFF48A",
            "7982B54C08DB2BFB6F45F35BC323BC093779B6BB0E3EEA3E8C98B1DE99D3C55E",
            "75E4162257014BEDCC05C2944DCE0DF0C35EBA131954064F6E4E095FD08445EE",
            "4A129EA6CDBABC2D392479372F975B9CF5A1B7DEB69A3266F03EBC6D111393C4",
            "8FED70F27955DC8AD9F1B7B3F6F5DFBD962A33592B42DE856D421E2912BAB86B",
            "E2F20660376F2B1839667CBFE5E16EF075AC3943644F3532282F8BB0723B9986",
            "ABF84C913A83DF98C70029819C065F6D6DE4F6D43ABF600DADE035B23BED7BAA",
            "459C15D4856C7ECF82620351C3C1C76C403F3E9707741387E299073FB1704B2B",
            "9AB912EDA0768ABDF826B6E05D0D735839E6A5F02E04C4CC75650B2C8CAB6749",
            "4740EBECAC90031BB7E68E51C55391AFB189B317F2DE558766F78F5CB71F81B6",
            "3CC47F0EF64821587C937CDDBA85C993D3CE2DD0CED40D3BE33CB7DC7EDABCF1",
            "9F476A22DB54D6BB9BEFDB260C66578AE1D8A5F87D3D8C017FDB7475080FA8E1",
            "8B68C6FB0706A795F3A839D6FE25FD4AA7F92E664F762D615381BC859AFA292C",
            "F640D225A6BCD2FC8ACCAFBED5A84B5BBB5D8AE5DB06A10B6D9D93160B392EE0",
            "704860A7F5BA68DB27031C15F225500D692AB247534281C4F684F6C6C8CD88C7",
            "C1A75BDDA12B8B2AB1B924843858183A09D202421FDBCDF0E63EAE46F37D91ED",
            "9A8CAB7A5F2E576221A6A85E5FDDEE75678E065324A61DB03A39261DDF75E3F4",
            "05C2B26B03CE6CA5871BE0DE84EE2786A79BCD9F30033E819B4A87CCA27AFC6A",
            "B0B0993C6D0C6ED5C3590480F865F467F4331A58DD8E47BD98EBBCDB8EB4F94D",
            "E57C103CF7B6BBEB8A0DC8F048625C3F4CE4F1A5AD4D079C1187BFE9EE3B8A5F",
            "F10023E15F3B72B738AD61AE65AB9A07E7774E2D7AB02DBA4E0CAF5602C80178",
            "9A8FB3B538C1D6C45051FA9ED9B07D3E89B4430330014A1EFA2823C0823CF237",
            "3075C5BC7C3AD7E3920101BC6899C58EA70167A7772CA28E38E2C1B0D325E5A0",
            "E85594700E3922A1E8E41EB8B064E7AC6D949D13B5A34523E5A6BEAC03C8AB29",
            "1D3701A5661BD31AB20562BD07B74DD19AC8F3524B73CE7BC996B788AFD2F317",
            "874E1938033D7D383597A2A65F58B554E41106F6D1D50E9BA0EB685F6B6DA071",
            "93F2F3D69B2D36529556ECCAF9F99ADBE895E1572231E649B50584B5D7D08AF8",
            "06E06D610F2EEBBA3676823E7744D751AFF73076ED65F3CFF5E72FD227999C77",
            "8DF757B3A1E0F480FA76C7F358ED0398BE3F2A8F7B90EA8C807599DEDA1D0534",
            "EEC9C5C63CC5169D967BB1624E9EE5CED92897736EFBD157548D82E87CC72F25",
            "CC2B5832AD272CC55C10D4F8C7F8BB38E6E4EB922F9386830F90B1E3DA3937D5",
            "368985D5387C0BFC928AC254FA6D16673E70947566961B5FB3325A588AB3173A",
            "F1E442AFB872151F8134956C548AE3240D07E6E338D4A7A6AF8DA4119AB0E2B0",
            "B012C7546A39C40CADECE4E04E7F33C593AD182EBC5A46D2DBF4AD1A92F59E7B",
            "6C6097CD2033096B4DF317DE8A908B7D0C7294390C5A399C301BF2A2652E8262",
            "BA83FEB510B49ADE4FAEFBE942781EAFD41AD5D436888531B68859F22C2D164A",
            "5A069E4392195AC9D284A47F3BD854AF8FD0D7FDC3483D2C5F3424CCFDA15C8E",
            "7E88D64BBBE2024F4454BA1398B3D8652DCEC820B14C3B0ABFBF0F4F3306BB5E",
            "F8742FF46DFDF3EC8264F9945B20419462F069E833C594EC80FFAC5E7E5134F9",
            "D3E0B738D2E92F3C47C794666609C0F5504F67EC4E760EEECCF8644E68333411",
            "0C90CE10EDF0CE1D47EEB50B5B7AFF8EE8A43B64A889C1C6C6B8E31A3CFC45EE",
            "83917AC1CDADE8F0E3BF426FEAC1388B3FCBE3E1BF98798C8158BF758E8D5D4E",
            "DC8EB0C013FA9D064EE37623369FB394AF974B1AAC82405B88976CD8FCA12530",
            "9AF4FC92EA8D6B5FE7990E3A02701EC22B2DFD7100B90D0551869417955E44C8",
            "C722CEC131BAA163F47E4B339E1FB9B4ACA248C4759345EADBD6C6A7DDB50477",
            "1837B120D4E4046C6DE8CCAF09F1CAF302AD56234E6B422CE90A61BF06AEE43D",
            "87AC9D0F8A0B11BFEDD6991A6DAF34C8AA5D7E8AE1B9DF4AF738005FE78CE93C",
            "E21FB668EBB8BF2D82086DEDCB3A5371C2C46FA1AC11D2E2C566D14AD3C3653F",
            "5A9A69815E4D3EB772ED908FE658CE5087310EC1D50CB94F5628339A61DCD9EE",
            "AAC285F1208F70A64797D0A9400DA64653301838FEF6690B87CDA9159EE07EF4",
            "05643C1C6F265925A65093F9DE8A191C4F6FD1418FBF66BE8059A91BA8DCDA61",
            "1C6CDE5B78103C9E6F046DFE30F5121CF9D4039EFE222540A41BBC06E469FEB6",
            "B49BB46D1B193B045E7412059FE72D552552A8FB6C36410723DC7D05FCCEDED3",
            "B612D3D21FC4DE3C791AF735E59FB717D839723B42508E9EBF7806D93E9C837F",
            "7C3390A3E5CB27D1868BA455CFEB3222FDE27BCDA4BF248E3D29CF1F34329F25",
            "BD42EEA7B35486CDD0907CB4712EDE2F4DEECCBCA191603865A1CC809F12B446",
            "D1DD6201740CFAAD53CECCB756B110F3D50F817B43D7559557E57AAD143A85D9",
            "5829643C1B10E1C8CCF20C9B4AF821EA052D7F0F7C22F7380BBBCFAFB977E21F",
            "FC4CF2A7FBE0B1E8AEFBE4B4B79ED84EC97B034F51B4E97F760B20639765B933",
            "4D7C3B3438A0BDA28E7A96E42027D813E88AE62885499833D3C5F6359EF7EDBC",
            "34CBD32068EF7E82099E580BF9E26423E981E31B1BBCE61AEAB14C32A273E4CB",
            "A05DDA7D0DA9E094AE22533F79E7DCCD26B1757CEFB95BCF62C4FF9C2692E1C0",
            "224CCFFA7CCA4CE34AFD47F62ADE53C5E8489B04AC9C41F7FAD0C8EDEB89E941",
            "6BC6076483AA11C07FBA55C0F9A1B5DA87ECBFFEA75598CC318A514CEC7B3B6A",
            "9A0360E23A22F4F76C0E9528DAFD129BB4675FB88D44EAF85777300CEC9BCC79",
            "790199B4CA90DEDCCFE32474E85B174F069E3542BE3104C1125C2FDBD69D32C7",
            "55839925834CA3E825E99241874D16D6C2623629C4C2ADDDF0DBA01E6CE8A0DC",
            "615FF846D993007D38DE1AECB3178289DED09E6BB5CBD60F69C6AA36383020F7",
            "F0E40B4ED40D34851E72B4EE4D00EA6A40EA1C1BF9E5C269710C9D51CBB8A3C9",
            "0B07B2333B08D08C11CA34AB449B71D29A0F43E1F778E073E79006CCB730ED62",
            "D1F4C29D9F23EA35EC4035B377D506538E728BC739C1459680CF1CC69424924D",
            "1279CF6F669F92F6BFC25D605B9440C7DCCBD25DF28DC7353ABC1C0530405DC4",
            "1FA0AF00775DC2CE76506D3280F472D2F6FF97A2151FAA827942FEA44AD0BA1F",
            "3E1AD54A5F835B983BD2AAB0ED2A4C0BDD7216209C36A79E9E2AABB99FAF3512",
            "C6ED39E2D8B636ECCBA245EF4E8864F4CD946BE216B9BE48303E08B92DD09434",
            "E24736C13ECB9F36A0D829D4798D7699C14CC65B6DC44ED6F10CD4853D6E0757",
            "389BE88052A381272C6DF741A88AD349B712718435480A8190B704771D2DE637",
            "889F2D578A5DAEFD341C210984E126D1D96DA2DEE3C81F7A6080BF84569B3114",
            "E936095B9B982FFC856D2F5276A4E529EC7395DA316D628702FB281ADA6F3899",
            "EF89CE1D6F8B48EA5CD6AEAB6A83D0CC98C9A3A207A1085732F047D94038C288",
            "F925016D79F2ACA8C49EDFCD6621D5BE3C8CEC61BD5871D8C1D3A565F35E0C9F",
            "63E8634B757A38F92B92FD23893BA299853A8613679FDF7E0511095C0F047BCA",
            "CF2CCA0772B705EB57D28943F83D353FE291E5B377780B374C8BA4665830BE87",
            "46DF5B87C80E7E4074AEE68559424742845B9B350F51BA55B074BBAE4C626AAB",
            "658AA4F9D2BCBD4F7F8EB63E68F5367EDBC500A0B1FBB41E9DF141BCBA8FCD53",
            "EE80555008A71655E081092BBA6F670ED98AF9A09FB5AFB94CBC5C754814DB4F",
            "2C5F9D048220B041B6D4524B4490CF8C66FCB8E14B0D64887AA1E4761A602B39",
            "44CB6311D0750B7E33F7333AA78AACA9C34AD5F79C1B1591EC33951E69C4C461",
            "0C6CE32A3EA05612C5F8090F6A7E87F5AB30E41B707DCBE54155620AD770A340",
            "C65938DD3A053C729CF5B7C89F390BFEBB5112766BB00AA5FA3164DFDF3B5647",
            "7DE7F0D59A9039AFF3AAF32C3EE52E7917535729062168D2490B6B6CE244B380",
            "895898F53A8F39E42410DA77B6C4815B0BB2395E3922F5BED0E1FBF2A4C6DFEB",
            "C905A84984348A64DB1F542083748AD90A4BAD9833CB6DA387293431F19E7C9C",
            "ED37D1A4D06C90D1957848667E9548FEBB5D423EAB4F56785CC4B5416B780008",
            "0BC65D9997FB734A561FB1E9F8C0958A02C7A4DBD096EBEF1A1751AED959EED7",
            "7C5F432EB8B7352A9494DEA4D53C21387031CE70E85D9408FC6F8CD98A6AAA1E",
            "B8BF8E2C34E033983639909EAA37640D877B048FE299B470AF2D0BA82A5F14C0",
            "88A9DD13D5DADBDEE6BFF7EE1EF8C71CC193AA4BF3E84F8FE80CB075683C0779",
            "9AEDB8876DD21C8C84D2E702A13625980462F68BF0A1B7254AD806C38403C9DE",
            "D097573DF2D6B2489A479484869800A1F833EA169EFF32AE3CE63A2079548D78",
            "D18F27A3E555D7F91A007C67ACEEDE391F75A61FA42A0B4566EB582CA05EBCE7",
            "DF1DAA90B1702313E6A5901C7AFC5ED9657717A715FA53A4189EC1E5DF293A68",
            "04E3A496B66996C66E32919ED1F94C36EEBBF240633A2F739845F0295D34AFBA",
            "8C45D88C4E9C9D0C8C677FE48FA5449BA30178D40AF0F0217921C62E4B60CDD3",
            "E149A6B13BDEDEA2EEEE009CE9445E8DCF76B76E55A501D8F5B43FF896796AD1",
            "A837C4C7C6F5CFB99E1085FD43287A4105CB28B76FC38B6055C5DCFF78B82565",
            "42411F28780B4F1638540B870521EC45BCEB1E0C7131F7E1C4672E436C88C8E9",
            "34B4E876769471DF552E5522CEA784FA53AC61BEDE8CFE291409E68B69E8776F",
            "8F31D637A91DBD0ECB0BA0E694BEC1447658CE6C27EA9B95FF36701CAF36F001",
            "B5C895EB071E3D38528D475D3BB0BA88B71795E40A982E2AC2D84422A0F2685D",
            "E906257C419D941ED2B8A9C12781DB9759A3FCF3DC7CDB031599E1086B672F10",
            "98AD24397C6EAE4CF73EA8BBEF5A0B74D21AD15F33920F44070A98BDF53D0B3A",
            "DD510CA55B1170F9CEFDBB16FC145262AA363A870A01E1BC4FBE40234B4B6F2F",
            "F2D8D931B92E1CB698E56ED02819EA11D26619B83A6209AD67225368FE119571",
            "E4637055DB91F9437CF460EF40B5145F6998266A5E74E96A00782C62CF30CF1C",
            "3563530A89D32B75F78D83E9872AD4C575F520399D65035DED99E5EEC5807150",
            "8E79F92C865BEB3E1CDBF08F754A2606E85349053D66D616024A813FCA541A4D",
            "864226F2839C76B1D5F7C13D98C2A5158C2ABB71D9D8F0FA1F7C3F7468001603",
            "D3E3F5B8CEEBB11184803535900B6EEDDA606EEB369751A7CDA36CA30229FB02",
            "8C7D6B987269169031F71FD7E4C445012D3E6A3C8809F6479BD667CF311E276E",
            "B904B5711BF19E8532F7AD6427410A62A1F77F77B9B6D71D2FC43BC90F73235A",
            "4536634315C86728F5AB7449EB2D04020E9EAE8DD6795500E9EC9A0066386E69",
            "FD5E49FED49DC44BDE89F460A950191EBB067C698A3F21EA14308C7413B91681",
            "31F01D030B9B22D00A0F71ED2CEB5D2DC81AF2C24BF5670FDE19A685E8D1392E",
            "5F84D9DE284B1E4F678E31AB6A76F5661B5AEAA768539384AA38F9E49CCE6E6E",
            "B2079E5997A4EAD3A71FEFC02F90A7483A10FD2E6F31BDA9D2084485CC016BBD",
            "E0F84D7F525B6FED791F77289AE58F7D50A29432D42C25C1E83929B838891D79",
            "70469690956D7918ACE7BA5F41302DA138C9B56ECD415544FACE8D998C21ABEB",
            "45C91A62249B39CDA94E508295BEC7667119447765EF80EFA82D1E92D57067D8",
            "1D9E0073EED0731554C3BEAA47460D511AD261DD4D4A3BED9D8D202F22F21589",
            "408262736D8AEC0B847DBA250258608A4345A63A1EB195E5C7AE2EE874C34DA8",
            "23D2B70439469949982390538D7E5ADE9F18C8E3BBF6605AFCF49B00C061E837",
            "232FB187D271BEA912EFD407FFE08056D6A42E5321EC792DF3D584A94F630AB2",
            "138E1944E4B54DE8681D7E48C4F08148E40A567E5CAD946A6AF4E8D5D26F75C7",
            "80C151325FBFC678B7BE4E40B30F29FE31CDBE1C84126E006DF3C18524BD2D6C",
            "A642267301669DF261B839F87365762905FF320A0A2FC4BDC48E5A8E15D13233",
            "0F8B10993860937A74CC2DE40A2731DD9954B654BB94C34E876652E98D4BBD16",
            "E634A58512493273260F10D44953CD998E34CB8281C41BF42E0AE2F25CBD1F75",
            "BDE6AF9BAF3C07E95423CAB504DEE70EDCC3318B22DD1EB6FD85BE447AC9F209",
            "914B37AB5B8CFDE6A480466A0D82432C7D76328E9A88EF5B4F52429F7A3FFC7D",
            "55BE66E9A5AA671A23882EF3E7D9D36EA95487DC71B725A5AD4B798A879143D0",
            "3FD045894B836E44E9CA75FBE3EADC486CBBD0D8CEE1B3CF14F76E7F1E77AEF3",
            "CE60343DC4874B6604E1FB231E37EC1EEC3F06566E428AE764EFFFA230ADD485",
            "E38C9DF024DE2153D226738A0E5BA9B8C6784DACA65C22A7628EB58EA0D495A7",
            "8DFEC0D4F3658A20A0BAD66F2160832B164E700A21EC5A0165C36772B2086111",
            "4401B50E09865F4238243B8225CA40A08DBB4685F5F862FBDD72980431A85D3F",
            "8668942788C4CE8A33190FFCFAD1C678C4FA41E99417094E240F4A43F387A3B6",
            "A7288D5E09809B696984ECD5326CDD84FBE35FCF67235D811C82002536A3C5E1",
            "8E925C3C146BACF3351EC53241ACE5F73E8FC9BD8C61CAD97FD772B07E1B8373",
            "C7EB9E6DED2F993D48B0170DA27C5B753B12176BE126C7BA2D6AF85F8593B752",
            "CA27F16F94E4EC0E628E7F8AEFC6657BEDC93742965940AE786A73B5FD593B97",
            "8C21E6568BC6DC00E3D6EBC09EA9C2CE006CD311D3B3E9CC9D8DDBFB3C5A7776",
            "525666968B3B7D007BB926B6EFDC7E212A31154C9AE18D43EE0EB7E6B1A938D3",
            "E09A4FA5C28BDCD7C839840E0A383E4F7A102D0B1BC849C949627C4100C17DD3",
            "C19F3E295DB2FC0E7481C4F16AF01155DDB0D7D1383D4A1FF1699DB71177340C",
            "769E678C0A0909A2021C4DC26B1A3C9BC557ADB21A50834CDC5C9293F75365F8",
            "B64874ADAB6BCB85B94BD9A6C565D0D2BC35445D7528BC85B41FDC79DC76E34F",
            "FAF250DE15820F7FC610DD53EEAE44601C3EFFA3ACCD088EB66905BB2653BE8C",
            "1E2038739B2C018B0E9E0E1E522FD9651287EE6E3665919B24C2124F0C1A3F3A",
            "5FEC3AA00861DE1AC5DAB3C137065D1E01BB03F69DCC7D1CF7CA4F4356AEC9A3",
            "4451FE6BBEF39343919244C51DAE1EA9A954CF2C0966AB045B15521ECF350081",
            "8C622FA2160E8E991813F180BFEC0B431C6DBFA2956D9175816A23C382C4F200",
            "817D5C8F92E7B5CA57F5E1639016AD5760E446D6E9CAA7498414ACE82280B5CD",
            "A6A1AD58CEE54E69CBBCAA87DF07A6707EB224739C217613460AB454B459CA9C",
            "63B847275226605BE67681258F7D00BBB307C66F1959BF2E467A41AEE714E55C",
            "FE52EBE5CFCFE6A2297B539FA3DADBD6EBD201AA2CA13563E3D7F14D15ABFF63",
            "B7BEF9FA5A3D10426246B5F658C08FDF8066EAA3E55A2F7DA1591E05C87DF8C7",
            "DED1D6CAA9F8F3BDA92CEA7F6549B1FB86A2211478C4EC289B837EFC2B5C27D7",
            "9F30008A2EB050F18E56A76BE92091B2FDC164D56E32C87DD64C9E3A611041B1",
            "010B6A3B11860088F0ABC80A8972CBBC329D5275342950EB9A045AFDC8BBED24",
            "0CD210AAC11F1C1CED497F673E53DB68C3EC3607F0C5787DDC60A355DFE56C25",
            "0E56FD01DA3B4F8BE2C990552AAC8D1E8DA209BCF4AAD4FFB5427FD63172463E",
            "D6D5CDB11440E34ACA3A2FCF30F59E08B11A2A3DE539E3E6513ED78A4FEE513B",
            "AA35AC90680670C732ED1EF37E8CBAAE49A4D88ECF4DF2B689A0F101B756AE47",
            "278E561288722630E26A5FC954BF2DCD6A65816739ABEE7BE14307A96174E5B0",
            "AB4B2CA1A2B349981524B6155462F0FF1060BF9BFA07FB9EC69CA471645B6A18",
            "18A9BBEC3C8E1F8EE9571297A93436DE427CD270EC69DFE888DB7DBF10B64993",
            "BAFC7E43D265A173021A9D9E583D60ED42A803FACD6B8360DE1F916835389BF0",
            "A5B67BE950FBC2F0DD323A79A19E3ED1F4AE4BA7894F930EA5EF734DE7DB83AE",
            "BF1E65F3CD8498884D9D5C19EBF7B916067637604E26DBE2B7288ECB11426068",
            "C3342CF9CBBF29D406D7895DD4D9548D4AC78B4D00E9B63E203E5E19E9974620",
            "1C0BE60277434B0E004B7B388A37559F84B30C6CF8600F528BFCD33CAF52CB1E",
            "73954530D03F10BEF52AD5BC7FB4C076F83F6331C8BD1EEEC3887F4AA2069240",
            "69C11EE04944DEA985AC9F13960E73980E1BB0E309F4384A1676F8EFAB384288",
            "36FB8FDE0EC28CE853FB7175C1B79DA3B5E8C39186E78AAECE5464DBD9FE2AA2",
            "6BB2A09DFCAF96962DE00C8A082D6DF9322B4966AE8D2ECF732411A76A1A0EE6",
            "7412E7DD1BF1AA9397411BBA4D3E0276D2E7A1A29A2477157AD60360D33D4E76",
            "DDDEAFCFC72321C849FB25947AB42C1AF2A5E43FEF681BE42C7EAF3660080AD3",
            "9DEFEBADBDCB0A0E7FF992F947CED3D0A4C899E64FE77360E81E1F0E97F8C1A2",
            "844C59FBE6476FD189239954F17E36E1F69E24AAED5D5C8B8405EF2A830CC2A0",
            "FF3FAFB67786E01A0C38EADF99C4CAE8029DA8CF29875FC419BF680009B3BDB3",
            "CA6760F345678F30A28D628294272A19E3072EBC61B19FF13B318973E97C2738",
            "C08E1A9047C505264A16447C9ED981A719D381F28E605FD7CAA9E8BDBB42996A",
            "F173BA9D4584CD126050C69FC219A9190A0BF0AECECBE611BEED193DA6CA4DE7",
            "B184876520DED8BD7DE25EAEFBD3E03688C3BE39C19FB73E1F0ECCAC7CC0F014",
            "9025DB0758BDFB48F0667EBD7E120246598FED01C258764FA0FAE334A2A00A97",
            "E83D8086FABC460D5EFC459F95A268F5DC4AC284093C247CA6EC841AD6183FE1",
            "CC9DF41D35AA75928C185F7393666110B80F0986A221C370F45C2EB9016C9A3B",
            "92F9A594954590FA819817E5D1C28AAB2B1CC504D86DBA443676BDF866796811",
            "729562A1E07B0E2605494809BD480F1537CEA10DCAD43EF9F68C66E825DC46B1",
            "26F160AB96F5582045146EAFF2E2A8D4DAB298B4C57E117CDFC5D025C92A2268",
            "87EBE721383873D247F86182E3F599A7634FCAEC5E07B1E83EBB79625BA354E6",
            "E08D389F75694ADC996C22F55D4F859FFD0C1319FF9CEDF78C31BE84B6F21ABC",
            "1363E22913C6E18E7AA65B83E751C8A2C61B0F307155865A57DBA569A99C7B0E",
            "8878088EB2D1F6D0BB481B4BB187DA04BCD8C2C639F005B08054CC41753905FB",
            "0418D60D05B4E124646EE50E7749A1D209457BC543E3CC1130274AEA0F7BF3C1",
            "7A397E503F293BC42D5F7EF5EC37872460A4F5B5CCDE77FB4D47AC0681E5A049",
            "5C0D2983E72A6DD4E652D723C1DFC12B414C873D4AB4A0A150408EB34347E995",
            "5623365453C04989C7CF33635E0FC4CDDD686FC95A33DFEDCF3335794C7DC344",
            "11F6DAD188028FDF1378A256E4570E9063107B8F79DC663FA5556F56FD44A0F0",
            "0ED8161797ECEE881E7D0E3F4C5FB839C84EB7A9242657CC48306807B32BEFDE",
            "736667C9364CE12DB8F6B143C6C178CDEF1E1445BC5A2F2634F08E9932273CAA",
            "E15F368B4406C1F65557C8355CBE694B633E26F155F52B7DA94CFB23FD4A5D96",
            "437AB2D74F50CA86CC3DE9BE70E4554825E33D824B3A492362E2E9D611BC579D",
            "2B9158C722898E526D2CDD3FC088E9FFA79A9B73B7D2D24BC478E21CDB3B6763",
            "0C8A36597D7461C63A94732821C941856C668376606C86A52DE0EE4104C615DB"
        };

    } // end class Blake2SPTestVectors
}
