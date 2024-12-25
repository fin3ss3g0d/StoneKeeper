#pragma once
#include <Windows.h>
#include <memory>
#include <vector>

class SecureString;
class SecureWideString;

typedef ULONG NET_IFINDEX, * PNET_IFINDEX;       // Interface Index (ifIndex)
typedef UINT16 NET_IFTYPE, * PNET_IFTYPE;        // Interface Type (IANA ifType)
typedef NET_IFINDEX IF_INDEX, * PIF_INDEX;

typedef enum {
    //
    // These values are from iptypes.h.
    // They need to fit in a 4 bit field.
    //
    IpPrefixOriginOther = 0,
    IpPrefixOriginManual,
    IpPrefixOriginWellKnown,
    IpPrefixOriginDhcp,
    IpPrefixOriginRouterAdvertisement,
    IpPrefixOriginUnchanged = 1 << 4
} NL_PREFIX_ORIGIN;

typedef enum {
    //
    // TODO: Remove the Nlso* definitions.
    //
    NlsoOther = 0,
    NlsoManual,
    NlsoWellKnown,
    NlsoDhcp,
    NlsoLinkLayerAddress,
    NlsoRandom,

    //
    // These values are from in iptypes.h.
    // They need to fit in a 4 bit field.
    //
    IpSuffixOriginOther = 0,
    IpSuffixOriginManual,
    IpSuffixOriginWellKnown,
    IpSuffixOriginDhcp,
    IpSuffixOriginLinkLayerAddress,
    IpSuffixOriginRandom,
    IpSuffixOriginUnchanged = 1 << 4
} NL_SUFFIX_ORIGIN;

typedef enum {
    //
    // TODO: Remove the Nlds* definitions.
    //
    NldsInvalid,
    NldsTentative,
    NldsDuplicate,
    NldsDeprecated,
    NldsPreferred,

    //
    // These values are from in iptypes.h.
    //
    IpDadStateInvalid = 0,
    IpDadStateTentative,
    IpDadStateDuplicate,
    IpDadStateDeprecated,
    IpDadStatePreferred,
} NL_DAD_STATE;

typedef NL_PREFIX_ORIGIN IP_PREFIX_ORIGIN;
typedef NL_SUFFIX_ORIGIN IP_SUFFIX_ORIGIN;
typedef NL_DAD_STATE IP_DAD_STATE;

typedef struct _SOCKET_ADDRESS {
    _Field_size_bytes_(iSockaddrLength) LPSOCKADDR lpSockaddr;

    //  ESP: 791.
    //    _When_(
    //        lpSockaddr->sa_family == AF_INET,
    //        _Field_range_(>=, sizeof(SOCKADDR_IN)))
    //    _When_(
    //        lpSockaddr->sa_family == AF_INET6,
    //        _Field_range_(>=, sizeof(SOCKADDR_IN6)))
    INT iSockaddrLength;
} SOCKET_ADDRESS, * PSOCKET_ADDRESS, * LPSOCKET_ADDRESS;

typedef struct _IP_ADAPTER_UNICAST_ADDRESS_LH {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_UNICAST_ADDRESS_LH* Next;
    SOCKET_ADDRESS Address;

    IP_PREFIX_ORIGIN PrefixOrigin;
    IP_SUFFIX_ORIGIN SuffixOrigin;
    IP_DAD_STATE DadState;

    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG LeaseLifetime;
    UINT8 OnLinkPrefixLength;
} IP_ADAPTER_UNICAST_ADDRESS_LH,
* PIP_ADAPTER_UNICAST_ADDRESS_LH;

typedef  IP_ADAPTER_UNICAST_ADDRESS_LH IP_ADAPTER_UNICAST_ADDRESS;
typedef  IP_ADAPTER_UNICAST_ADDRESS_LH* PIP_ADAPTER_UNICAST_ADDRESS;

typedef struct _IP_ADAPTER_UNICAST_ADDRESS_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_UNICAST_ADDRESS_XP* Next;
    SOCKET_ADDRESS Address;

    IP_PREFIX_ORIGIN PrefixOrigin;
    IP_SUFFIX_ORIGIN SuffixOrigin;
    IP_DAD_STATE DadState;

    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG LeaseLifetime;
} IP_ADAPTER_UNICAST_ADDRESS_XP, * PIP_ADAPTER_UNICAST_ADDRESS_XP;

typedef struct _IP_ADAPTER_ANYCAST_ADDRESS_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_ANYCAST_ADDRESS_XP* Next;
    SOCKET_ADDRESS Address;
} IP_ADAPTER_ANYCAST_ADDRESS_XP, * PIP_ADAPTER_ANYCAST_ADDRESS_XP;

typedef struct _IP_ADAPTER_MULTICAST_ADDRESS_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_MULTICAST_ADDRESS_XP* Next;
    SOCKET_ADDRESS Address;
} IP_ADAPTER_MULTICAST_ADDRESS_XP, * PIP_ADAPTER_MULTICAST_ADDRESS_XP;

typedef struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Reserved;
        };
    };
    struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP* Next;
    SOCKET_ADDRESS Address;
} IP_ADAPTER_DNS_SERVER_ADDRESS_XP, * PIP_ADAPTER_DNS_SERVER_ADDRESS_XP;

typedef IP_ADAPTER_DNS_SERVER_ADDRESS_XP IP_ADAPTER_DNS_SERVER_ADDRESS;
typedef IP_ADAPTER_DNS_SERVER_ADDRESS_XP* PIP_ADAPTER_DNS_SERVER_ADDRESS;

#define MAX_ADAPTER_ADDRESS_LENGTH 8 // arb.
#define MAX_DHCPV6_DUID_LENGTH 130 // RFC 3315.
#define MAX_DNS_SUFFIX_STRING_LENGTH 256
#define GAA_FLAG_INCLUDE_PREFIX 0x0010
#define INET_ADDRSTRLEN  22
#define INET6_ADDRSTRLEN 65
#define AF_INET6 23 // Internetwork Version 6

//
// Bit values of IP_ADAPTER_ADDRESSES Flags field.
//
#define IP_ADAPTER_DDNS_ENABLED               0x00000001
#define IP_ADAPTER_REGISTER_ADAPTER_SUFFIX    0x00000002
#define IP_ADAPTER_DHCP_ENABLED               0x00000004
#define IP_ADAPTER_RECEIVE_ONLY               0x00000008
#define IP_ADAPTER_NO_MULTICAST               0x00000010
#define IP_ADAPTER_IPV6_OTHER_STATEFUL_CONFIG 0x00000020
#define IP_ADAPTER_NETBIOS_OVER_TCPIP_ENABLED 0x00000040
#define IP_ADAPTER_IPV4_ENABLED               0x00000080
#define IP_ADAPTER_IPV6_ENABLED               0x00000100
#define IP_ADAPTER_IPV6_MANAGE_ADDRESS_CONFIG 0x00000200

//////////////////////////////////////////////////////////////////////////////
//                                                                          //
// Media types                                                              //
//                                                                          //
// These are enumerated values of the ifType object defined in MIB-II's     //
// ifTable.  They are registered with IANA which publishes this list        //
// periodically, in either the Assigned Numbers RFC, or some derivative     //
// of it specific to Internet Network Management number assignments.        //
// See ftp://ftp.isi.edu/mib/ianaiftype.mib                                 //
//                                                                          //
//////////////////////////////////////////////////////////////////////////////

#define MIN_IF_TYPE                     1

#define IF_TYPE_OTHER                   1   // None of the below
#define IF_TYPE_REGULAR_1822            2
#define IF_TYPE_HDH_1822                3
#define IF_TYPE_DDN_X25                 4
#define IF_TYPE_RFC877_X25              5
#define IF_TYPE_ETHERNET_CSMACD         6
#define IF_TYPE_IS088023_CSMACD         7
#define IF_TYPE_ISO88024_TOKENBUS       8
#define IF_TYPE_ISO88025_TOKENRING      9
#define IF_TYPE_ISO88026_MAN            10
#define IF_TYPE_STARLAN                 11
#define IF_TYPE_PROTEON_10MBIT          12
#define IF_TYPE_PROTEON_80MBIT          13
#define IF_TYPE_HYPERCHANNEL            14
#define IF_TYPE_FDDI                    15
#define IF_TYPE_LAP_B                   16
#define IF_TYPE_SDLC                    17
#define IF_TYPE_DS1                     18  // DS1-MIB
#define IF_TYPE_E1                      19  // Obsolete; see DS1-MIB
#define IF_TYPE_BASIC_ISDN              20
#define IF_TYPE_PRIMARY_ISDN            21
#define IF_TYPE_PROP_POINT2POINT_SERIAL 22  // proprietary serial
#define IF_TYPE_PPP                     23
#define IF_TYPE_SOFTWARE_LOOPBACK       24
#define IF_TYPE_EON                     25  // CLNP over IP
#define IF_TYPE_ETHERNET_3MBIT          26
#define IF_TYPE_NSIP                    27  // XNS over IP
#define IF_TYPE_SLIP                    28  // Generic Slip
#define IF_TYPE_ULTRA                   29  // ULTRA Technologies
#define IF_TYPE_DS3                     30  // DS3-MIB
#define IF_TYPE_SIP                     31  // SMDS, coffee
#define IF_TYPE_FRAMERELAY              32  // DTE only
#define IF_TYPE_RS232                   33
#define IF_TYPE_PARA                    34  // Parallel port
#define IF_TYPE_ARCNET                  35
#define IF_TYPE_ARCNET_PLUS             36
#define IF_TYPE_ATM                     37  // ATM cells
#define IF_TYPE_MIO_X25                 38
#define IF_TYPE_SONET                   39  // SONET or SDH
#define IF_TYPE_X25_PLE                 40
#define IF_TYPE_ISO88022_LLC            41
#define IF_TYPE_LOCALTALK               42
#define IF_TYPE_SMDS_DXI                43
#define IF_TYPE_FRAMERELAY_SERVICE      44  // FRNETSERV-MIB
#define IF_TYPE_V35                     45
#define IF_TYPE_HSSI                    46
#define IF_TYPE_HIPPI                   47
#define IF_TYPE_MODEM                   48  // Generic Modem
#define IF_TYPE_AAL5                    49  // AAL5 over ATM
#define IF_TYPE_SONET_PATH              50
#define IF_TYPE_SONET_VT                51
#define IF_TYPE_SMDS_ICIP               52  // SMDS InterCarrier Interface
#define IF_TYPE_PROP_VIRTUAL            53  // Proprietary virtual/internal
#define IF_TYPE_PROP_MULTIPLEXOR        54  // Proprietary multiplexing
#define IF_TYPE_IEEE80212               55  // 100BaseVG
#define IF_TYPE_FIBRECHANNEL            56
#define IF_TYPE_HIPPIINTERFACE          57
#define IF_TYPE_FRAMERELAY_INTERCONNECT 58  // Obsolete, use 32 or 44
#define IF_TYPE_AFLANE_8023             59  // ATM Emulated LAN for 802.3
#define IF_TYPE_AFLANE_8025             60  // ATM Emulated LAN for 802.5
#define IF_TYPE_CCTEMUL                 61  // ATM Emulated circuit
#define IF_TYPE_FASTETHER               62  // Fast Ethernet (100BaseT)
#define IF_TYPE_ISDN                    63  // ISDN and X.25
#define IF_TYPE_V11                     64  // CCITT V.11/X.21
#define IF_TYPE_V36                     65  // CCITT V.36
#define IF_TYPE_G703_64K                66  // CCITT G703 at 64Kbps
#define IF_TYPE_G703_2MB                67  // Obsolete; see DS1-MIB
#define IF_TYPE_QLLC                    68  // SNA QLLC
#define IF_TYPE_FASTETHER_FX            69  // Fast Ethernet (100BaseFX)
#define IF_TYPE_CHANNEL                 70
#define IF_TYPE_IEEE80211               71  // Radio spread spectrum
#define IF_TYPE_IBM370PARCHAN           72  // IBM System 360/370 OEMI Channel
#define IF_TYPE_ESCON                   73  // IBM Enterprise Systems Connection
#define IF_TYPE_DLSW                    74  // Data Link Switching
#define IF_TYPE_ISDN_S                  75  // ISDN S/T interface
#define IF_TYPE_ISDN_U                  76  // ISDN U interface
#define IF_TYPE_LAP_D                   77  // Link Access Protocol D
#define IF_TYPE_IPSWITCH                78  // IP Switching Objects
#define IF_TYPE_RSRB                    79  // Remote Source Route Bridging
#define IF_TYPE_ATM_LOGICAL             80  // ATM Logical Port
#define IF_TYPE_DS0                     81  // Digital Signal Level 0
#define IF_TYPE_DS0_BUNDLE              82  // Group of ds0s on the same ds1
#define IF_TYPE_BSC                     83  // Bisynchronous Protocol
#define IF_TYPE_ASYNC                   84  // Asynchronous Protocol
#define IF_TYPE_CNR                     85  // Combat Net Radio
#define IF_TYPE_ISO88025R_DTR           86  // ISO 802.5r DTR
#define IF_TYPE_EPLRS                   87  // Ext Pos Loc Report Sys
#define IF_TYPE_ARAP                    88  // Appletalk Remote Access Protocol
#define IF_TYPE_PROP_CNLS               89  // Proprietary Connectionless Proto
#define IF_TYPE_HOSTPAD                 90  // CCITT-ITU X.29 PAD Protocol
#define IF_TYPE_TERMPAD                 91  // CCITT-ITU X.3 PAD Facility
#define IF_TYPE_FRAMERELAY_MPI          92  // Multiproto Interconnect over FR
#define IF_TYPE_X213                    93  // CCITT-ITU X213
#define IF_TYPE_ADSL                    94  // Asymmetric Digital Subscrbr Loop
#define IF_TYPE_RADSL                   95  // Rate-Adapt Digital Subscrbr Loop
#define IF_TYPE_SDSL                    96  // Symmetric Digital Subscriber Loop
#define IF_TYPE_VDSL                    97  // Very H-Speed Digital Subscrb Loop
#define IF_TYPE_ISO88025_CRFPRINT       98  // ISO 802.5 CRFP
#define IF_TYPE_MYRINET                 99  // Myricom Myrinet
#define IF_TYPE_VOICE_EM                100 // Voice recEive and transMit
#define IF_TYPE_VOICE_FXO               101 // Voice Foreign Exchange Office
#define IF_TYPE_VOICE_FXS               102 // Voice Foreign Exchange Station
#define IF_TYPE_VOICE_ENCAP             103 // Voice encapsulation
#define IF_TYPE_VOICE_OVERIP            104 // Voice over IP encapsulation
#define IF_TYPE_ATM_DXI                 105 // ATM DXI
#define IF_TYPE_ATM_FUNI                106 // ATM FUNI
#define IF_TYPE_ATM_IMA                 107 // ATM IMA
#define IF_TYPE_PPPMULTILINKBUNDLE      108 // PPP Multilink Bundle
#define IF_TYPE_IPOVER_CDLC             109 // IBM ipOverCdlc
#define IF_TYPE_IPOVER_CLAW             110 // IBM Common Link Access to Workstn
#define IF_TYPE_STACKTOSTACK            111 // IBM stackToStack
#define IF_TYPE_VIRTUALIPADDRESS        112 // IBM VIPA
#define IF_TYPE_MPC                     113 // IBM multi-proto channel support
#define IF_TYPE_IPOVER_ATM              114 // IBM ipOverAtm
#define IF_TYPE_ISO88025_FIBER          115 // ISO 802.5j Fiber Token Ring
#define IF_TYPE_TDLC                    116 // IBM twinaxial data link control
#define IF_TYPE_GIGABITETHERNET         117
#define IF_TYPE_HDLC                    118
#define IF_TYPE_LAP_F                   119
#define IF_TYPE_V37                     120
#define IF_TYPE_X25_MLP                 121 // Multi-Link Protocol
#define IF_TYPE_X25_HUNTGROUP           122 // X.25 Hunt Group
#define IF_TYPE_TRANSPHDLC              123
#define IF_TYPE_INTERLEAVE              124 // Interleave channel
#define IF_TYPE_FAST                    125 // Fast channel
#define IF_TYPE_IP                      126 // IP (for APPN HPR in IP networks)
#define IF_TYPE_DOCSCABLE_MACLAYER      127 // CATV Mac Layer
#define IF_TYPE_DOCSCABLE_DOWNSTREAM    128 // CATV Downstream interface
#define IF_TYPE_DOCSCABLE_UPSTREAM      129 // CATV Upstream interface
#define IF_TYPE_A12MPPSWITCH            130 // Avalon Parallel Processor
#define IF_TYPE_TUNNEL                  131 // Encapsulation interface
#define IF_TYPE_COFFEE                  132 // Coffee pot
#define IF_TYPE_CES                     133 // Circuit Emulation Service
#define IF_TYPE_ATM_SUBINTERFACE        134 // ATM Sub Interface
#define IF_TYPE_L2_VLAN                 135 // Layer 2 Virtual LAN using 802.1Q
#define IF_TYPE_L3_IPVLAN               136 // Layer 3 Virtual LAN using IP
#define IF_TYPE_L3_IPXVLAN              137 // Layer 3 Virtual LAN using IPX
#define IF_TYPE_DIGITALPOWERLINE        138 // IP over Power Lines
#define IF_TYPE_MEDIAMAILOVERIP         139 // Multimedia Mail over IP
#define IF_TYPE_DTM                     140 // Dynamic syncronous Transfer Mode
#define IF_TYPE_DCN                     141 // Data Communications Network
#define IF_TYPE_IPFORWARD               142 // IP Forwarding Interface
#define IF_TYPE_MSDSL                   143 // Multi-rate Symmetric DSL
#define IF_TYPE_IEEE1394                144 // IEEE1394 High Perf Serial Bus
#define IF_TYPE_IF_GSN                  145
#define IF_TYPE_DVBRCC_MACLAYER         146
#define IF_TYPE_DVBRCC_DOWNSTREAM       147
#define IF_TYPE_DVBRCC_UPSTREAM         148
#define IF_TYPE_ATM_VIRTUAL             149
#define IF_TYPE_MPLS_TUNNEL             150
#define IF_TYPE_SRP                     151
#define IF_TYPE_VOICEOVERATM            152
#define IF_TYPE_VOICEOVERFRAMERELAY     153
#define IF_TYPE_IDSL                    154
#define IF_TYPE_COMPOSITELINK           155
#define IF_TYPE_SS7_SIGLINK             156
#define IF_TYPE_PROP_WIRELESS_P2P       157
#define IF_TYPE_FR_FORWARD              158
#define IF_TYPE_RFC1483                 159
#define IF_TYPE_USB                     160
#define IF_TYPE_IEEE8023AD_LAG          161
#define IF_TYPE_BGP_POLICY_ACCOUNTING   162
#define IF_TYPE_FRF16_MFR_BUNDLE        163
#define IF_TYPE_H323_GATEKEEPER         164
#define IF_TYPE_H323_PROXY              165
#define IF_TYPE_MPLS                    166
#define IF_TYPE_MF_SIGLINK              167
#define IF_TYPE_HDSL2                   168
#define IF_TYPE_SHDSL                   169
#define IF_TYPE_DS1_FDL                 170
#define IF_TYPE_POS                     171
#define IF_TYPE_DVB_ASI_IN              172
#define IF_TYPE_DVB_ASI_OUT             173
#define IF_TYPE_PLC                     174
#define IF_TYPE_NFAS                    175
#define IF_TYPE_TR008                   176
#define IF_TYPE_GR303_RDT               177
#define IF_TYPE_GR303_IDT               178
#define IF_TYPE_ISUP                    179
#define IF_TYPE_PROP_DOCS_WIRELESS_MACLAYER      180
#define IF_TYPE_PROP_DOCS_WIRELESS_DOWNSTREAM    181
#define IF_TYPE_PROP_DOCS_WIRELESS_UPSTREAM      182
#define IF_TYPE_HIPERLAN2                        183
#define IF_TYPE_PROP_BWA_P2MP                    184
#define IF_TYPE_SONET_OVERHEAD_CHANNEL           185
#define IF_TYPE_DIGITAL_WRAPPER_OVERHEAD_CHANNEL 186
#define IF_TYPE_AAL2                             187
#define IF_TYPE_RADIO_MAC                        188
#define IF_TYPE_ATM_RADIO                        189
#define IF_TYPE_IMT                              190
#define IF_TYPE_MVL                              191
#define IF_TYPE_REACH_DSL                        192
#define IF_TYPE_FR_DLCI_ENDPT                    193
#define IF_TYPE_ATM_VCI_ENDPT                    194
#define IF_TYPE_OPTICAL_CHANNEL                  195
#define IF_TYPE_OPTICAL_TRANSPORT                196
#define IF_TYPE_IEEE80216_WMAN                   237
#define IF_TYPE_WWANPP                  243 // WWAN devices based on GSM technology
#define IF_TYPE_WWANPP2                 244 // WWAN devices based on CDMA technology
#define IF_TYPE_IEEE802154              259 // IEEE 802.15.4 WPAN interface
#define IF_TYPE_XBOX_WIRELESS           281

#define MAX_IF_TYPE                     281

typedef ULONG IFTYPE;

typedef enum {
    IfOperStatusUp = 1,
    IfOperStatusDown,
    IfOperStatusTesting,
    IfOperStatusUnknown,
    IfOperStatusDormant,
    IfOperStatusNotPresent,
    IfOperStatusLowerLayerDown
} IF_OPER_STATUS;

typedef struct _IP_ADAPTER_PREFIX_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_PREFIX_XP* Next;
    SOCKET_ADDRESS Address;
    ULONG PrefixLength;
} IP_ADAPTER_PREFIX_XP, * PIP_ADAPTER_PREFIX_XP;

typedef struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Reserved;
        };
    };
    struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH* Next;
    SOCKET_ADDRESS Address;
} IP_ADAPTER_WINS_SERVER_ADDRESS_LH, * PIP_ADAPTER_WINS_SERVER_ADDRESS_LH;

typedef struct _IP_ADAPTER_GATEWAY_ADDRESS_LH {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Reserved;
        };
    };
    struct _IP_ADAPTER_GATEWAY_ADDRESS_LH* Next;
    SOCKET_ADDRESS Address;
} IP_ADAPTER_GATEWAY_ADDRESS_LH, * PIP_ADAPTER_GATEWAY_ADDRESS_LH;

#pragma warning(push)
#pragma warning(disable:4214) // bit field types other than int
typedef union _NET_LUID_LH
{
    ULONG64     Value;
    struct
    {
        ULONG64     Reserved : 24;
        ULONG64     NetLuidIndex : 24;
        ULONG64     IfType : 16;                  // equal to IANA IF type
    }Info;
} NET_LUID_LH, * PNET_LUID_LH;
#pragma warning(pop)

typedef NET_LUID_LH NET_LUID;
typedef NET_LUID* PNET_LUID;
typedef NET_LUID IF_LUID, * PIF_LUID;
typedef UINT32 NET_IF_COMPARTMENT_ID, * PNET_IF_COMPARTMENT_ID;
typedef GUID NET_IF_NETWORK_GUID, * PNET_IF_NETWORK_GUID;

typedef enum _NET_IF_CONNECTION_TYPE
{
    NET_IF_CONNECTION_DEDICATED = 1,
    NET_IF_CONNECTION_PASSIVE = 2,
    NET_IF_CONNECTION_DEMAND = 3,
    NET_IF_CONNECTION_MAXIMUM = 4
} NET_IF_CONNECTION_TYPE, * PNET_IF_CONNECTION_TYPE;

typedef enum {
    TUNNEL_TYPE_NONE = 0,
    TUNNEL_TYPE_OTHER = 1,
    TUNNEL_TYPE_DIRECT = 2,
    TUNNEL_TYPE_6TO4 = 11,
    TUNNEL_TYPE_ISATAP = 13,
    TUNNEL_TYPE_TEREDO = 14,
    TUNNEL_TYPE_IPHTTPS = 15,
} TUNNEL_TYPE, * PTUNNEL_TYPE;

typedef struct _IP_ADAPTER_DNS_SUFFIX {
    struct _IP_ADAPTER_DNS_SUFFIX* Next;
    WCHAR String[MAX_DNS_SUFFIX_STRING_LENGTH];
}IP_ADAPTER_DNS_SUFFIX, * PIP_ADAPTER_DNS_SUFFIX;

typedef struct _IP_ADAPTER_ADDRESSES_LH {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            IF_INDEX IfIndex;
        };
    };
    struct _IP_ADAPTER_ADDRESSES_LH* Next;
    PCHAR AdapterName;
    PIP_ADAPTER_UNICAST_ADDRESS_LH FirstUnicastAddress;
    PIP_ADAPTER_ANYCAST_ADDRESS_XP FirstAnycastAddress;
    PIP_ADAPTER_MULTICAST_ADDRESS_XP FirstMulticastAddress;
    PIP_ADAPTER_DNS_SERVER_ADDRESS_XP FirstDnsServerAddress;
    PWCHAR DnsSuffix;
    PWCHAR Description;
    PWCHAR FriendlyName;
    BYTE PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH];
    ULONG PhysicalAddressLength;
    union {
        ULONG Flags;
        struct {
            ULONG DdnsEnabled : 1;
            ULONG RegisterAdapterSuffix : 1;
            ULONG Dhcpv4Enabled : 1;
            ULONG ReceiveOnly : 1;
            ULONG NoMulticast : 1;
            ULONG Ipv6OtherStatefulConfig : 1;
            ULONG NetbiosOverTcpipEnabled : 1;
            ULONG Ipv4Enabled : 1;
            ULONG Ipv6Enabled : 1;
            ULONG Ipv6ManagedAddressConfigurationSupported : 1;
        };
    };
    ULONG Mtu;
    IFTYPE IfType;
    IF_OPER_STATUS OperStatus;
    IF_INDEX Ipv6IfIndex;
    ULONG ZoneIndices[16];
    PIP_ADAPTER_PREFIX_XP FirstPrefix;

    ULONG64 TransmitLinkSpeed;
    ULONG64 ReceiveLinkSpeed;
    PIP_ADAPTER_WINS_SERVER_ADDRESS_LH FirstWinsServerAddress;
    PIP_ADAPTER_GATEWAY_ADDRESS_LH FirstGatewayAddress;
    ULONG Ipv4Metric;
    ULONG Ipv6Metric;
    IF_LUID Luid;
    SOCKET_ADDRESS Dhcpv4Server;
    NET_IF_COMPARTMENT_ID CompartmentId;
    NET_IF_NETWORK_GUID NetworkGuid;
    NET_IF_CONNECTION_TYPE ConnectionType;
    TUNNEL_TYPE TunnelType;
    //
    // DHCP v6 Info.
    //
    SOCKET_ADDRESS Dhcpv6Server;
    BYTE Dhcpv6ClientDuid[MAX_DHCPV6_DUID_LENGTH];
    ULONG Dhcpv6ClientDuidLength;
    ULONG Dhcpv6Iaid;
#if (NTDDI_VERSION >= NTDDI_VISTASP1)
    PIP_ADAPTER_DNS_SUFFIX FirstDnsSuffix;
#endif
} IP_ADAPTER_ADDRESSES_LH,
* PIP_ADAPTER_ADDRESSES_LH;

typedef  IP_ADAPTER_ADDRESSES_LH IP_ADAPTER_ADDRESSES;
typedef  IP_ADAPTER_ADDRESSES_LH* PIP_ADAPTER_ADDRESSES;

typedef USHORT ADDRESS_FAMILY;

typedef struct in6_addr {
    union {
        UCHAR       Byte[16];
        USHORT      Word[8];
    } u;
} IN6_ADDR, * PIN6_ADDR, FAR* LPIN6_ADDR;

typedef struct {
    union {
        struct {
            ULONG Zone : 28;
            ULONG Level : 4;
        } DUMMYSTRUCTNAME;
        ULONG Value;
    } DUMMYUNIONNAME;
} SCOPE_ID, * PSCOPE_ID;

typedef struct sockaddr_in6 {
    ADDRESS_FAMILY sin6_family; // AF_INET6.
    USHORT sin6_port;           // Transport level port number.
    ULONG  sin6_flowinfo;       // IPv6 flow information.
    IN6_ADDR sin6_addr;         // IPv6 address.
    union {
        ULONG sin6_scope_id;     // Set of interfaces for a scope.
        SCOPE_ID sin6_scope_struct;
    };
} SOCKADDR_IN6_LH, * PSOCKADDR_IN6_LH, FAR* LPSOCKADDR_IN6_LH;

struct AdapterInfo {
    std::unique_ptr<SecureWideString> Name;
    std::vector<SecureString> IPAddresses;
    std::unique_ptr<SecureWideString> Description;
    std::unique_ptr<SecureString> MACAddress;
    std::unique_ptr<SecureWideString> DNSSuffix;
    std::vector<SecureWideString> DNSSuffixes; // Additional DNS Suffixes
    std::unique_ptr<SecureString> OperationalStatus;
    std::unique_ptr<SecureString> AdapterType;
    std::unique_ptr<SecureString> TunnelType;
    std::unique_ptr<SecureString> TransmitLinkSpeed;
    std::unique_ptr<SecureString> ReceiveLinkSpeed;
    std::vector<SecureString> DNSAddresses;
    std::vector<SecureString> WINSAddresses;
    std::vector<SecureString> GatewayAddresses;
    std::unique_ptr<SecureString> Dhcpv4Server;
    std::unique_ptr<SecureString> Dhcpv6Server;
    // Flags
    std::unique_ptr<SecureString> DdnsEnabled;
    std::unique_ptr<SecureString> RegisterAdapterSuffix;
    std::unique_ptr<SecureString> Dhcpv4Enabled;
    std::unique_ptr<SecureString> ReceiveOnly;
    std::unique_ptr<SecureString> NoMulticast;
    std::unique_ptr<SecureString> Ipv6OtherStatefulConfig;
    std::unique_ptr<SecureString> NetbiosOverTcpipEnabled;
    std::unique_ptr<SecureString> Ipv4Enabled;
    std::unique_ptr<SecureString> Ipv6Enabled;
    std::unique_ptr<SecureString> Ipv6ManagedAddressConfig;
};

class NetworkAdapters {
public:
    static NetworkAdapters& Get() {
        static NetworkAdapters networkAdapters; // Guaranteed to be destroyed and instantiated on first use.
        return networkAdapters;
    }

    // Public methods
    static std::vector<AdapterInfo> GetAllAdaptersInfo();
    // Task methods
    static void CALLBACK GetAllAdaptersInfo(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

    // Public members

    // Delete copy/move constructors and assignment operators
    NetworkAdapters(NetworkAdapters const&) = delete;
    void operator=(NetworkAdapters const&) = delete;
    NetworkAdapters(NetworkAdapters&&) = delete;
    void operator=(NetworkAdapters&&) = delete;

private:
    NetworkAdapters() {};

    // Private methods
    static SecureString sockaddr_to_ip(SOCKADDR* sockaddr);
    static void processUnicastAddresses(PIP_ADAPTER_ADDRESSES adapter, std::vector<SecureString>& ipAddresses);
    static void processDnsServerAddresses(PIP_ADAPTER_ADDRESSES adapter, std::vector<SecureString>& dnsAddresses);
    static void processWinsServerAddresses(PIP_ADAPTER_ADDRESSES adapter, std::vector<SecureString>& winsAddresses);
    static void processGatewayAddresses(PIP_ADAPTER_ADDRESSES adapter, std::vector<SecureString>& gatewayAddresses);
    static void processDnsSuffixes(PIP_ADAPTER_ADDRESSES adapter, std::vector<SecureWideString>& dnsSuffixes);
    static void processOperationalStatus(PIP_ADAPTER_ADDRESSES adapter, AdapterInfo& adapterInfo);
    static void processAdapterType(PIP_ADAPTER_ADDRESSES adapter, AdapterInfo& adapterInfo);
    static void processTunnelType(PIP_ADAPTER_ADDRESSES adapter, AdapterInfo& adapterInfo);
    static void processLinkSpeeds(PIP_ADAPTER_ADDRESSES adapter, AdapterInfo& adapterInfo);
    static void processPhysicalAddress(PIP_ADAPTER_ADDRESSES adapter, AdapterInfo& adapterInfo);
    static void processDhcpServer(PIP_ADAPTER_ADDRESSES adapter, AdapterInfo& adapterInfo, bool v4);
    static void processFlags(PIP_ADAPTER_ADDRESSES adapter, AdapterInfo& adapterInfo);
    static bool isValid(const std::unique_ptr<SecureString>& str);
    static bool isValid(const std::unique_ptr<SecureWideString>& str);    

    // Private members
};
