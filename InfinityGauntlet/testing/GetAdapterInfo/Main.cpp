#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

struct AdapterInfo {
    std::wstring Name;
    std::vector<std::string> IPAddresses;
    std::wstring Description;
    std::string MACAddress;
    std::wstring DNSSuffix;
    std::vector<std::wstring> DNSSuffixes; // Additional DNS Suffixes
    std::string OperationalStatus;
    std::string AdapterType;
    std::string TunnelType;
    std::string TransmitLinkSpeed;
    std::string ReceiveLinkSpeed;
    std::vector<std::string> DNSAddresses;
    std::vector<std::string> WINSAddresses;
    std::vector<std::string> GatewayAddresses;
    std::string Dhcpv4Server;
    std::string Dhcpv6Server;
    // Flags
    std::string DdnsEnabled;
    std::string RegisterAdapterSuffix;
    std::string Dhcpv4Enabled;
    std::string ReceiveOnly;
    std::string NoMulticast;
    std::string Ipv6OtherStatefulConfig;
    std::string NetbiosOverTcpipEnabled;
    std::string Ipv4Enabled;
    std::string Ipv6Enabled;
    std::string Ipv6ManagedAddressConfig;
};

std::vector<AdapterInfo> GetAllAdaptersInfo() {
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &bufferSize);
    std::vector<BYTE> buffer(bufferSize);
    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);

    std::vector<AdapterInfo> adapters;
    if (ret == NO_ERROR) {
        IP_ADAPTER_ADDRESSES* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        while (adapter) {
            AdapterInfo info;
            info.Name = adapter->FriendlyName;
            info.Description = adapter->Description;
            info.DNSSuffix = adapter->DnsSuffix;
            info.OperationalStatus = adapter->OperStatus == IfOperStatusUp ? "Up" : "Down";

            // Adapter Type
            switch (adapter->IfType) {
				case IF_TYPE_OTHER:
					info.AdapterType = "Other";
					break;
				case IF_TYPE_ETHERNET_CSMACD:
					info.AdapterType = "Ethernet";
					break;
				case IF_TYPE_ISO88025_TOKENRING:
					info.AdapterType = "Token Ring";
					break;
				case IF_TYPE_PPP:
					info.AdapterType = "PPP";
					break;
				case IF_TYPE_SOFTWARE_LOOPBACK:
					info.AdapterType = "Loopback";
					break;
				case IF_TYPE_ATM:
					info.AdapterType = "ATM";
					break;
                case IF_TYPE_PROP_VIRTUAL:
					info.AdapterType = "Virtual (VPN)";
					break;
				case IF_TYPE_IEEE80211:
					info.AdapterType = "IEEE 802.11 Wireless";
					break;
				case IF_TYPE_TUNNEL:
					info.AdapterType = "Tunnel";
					break;
				case IF_TYPE_IEEE1394:
					info.AdapterType = "IEEE 1394";
					break;
				case IF_TYPE_WWANPP:
					info.AdapterType = "WWANPP";
					break;
				case IF_TYPE_WWANPP2:
					info.AdapterType = "WWANPP2";
					break;
				default:
					info.AdapterType = "Unknown";
                    info.AdapterType += " (" + std::to_string(adapter->IfType) + ")";
					break;
			}

            // Tunnel Type
            switch (adapter->TunnelType) {
            case TUNNEL_TYPE_NONE:
                info.TunnelType = "NONE";
                break;
            case TUNNEL_TYPE_OTHER:
                info.TunnelType = "OTHER";
                break;
            case TUNNEL_TYPE_TEREDO:
                info.TunnelType = "TEREDO";
                break;
            case TUNNEL_TYPE_IPHTTPS:
                info.TunnelType = "IPHTTPS";
                break;
            case TUNNEL_TYPE_ISATAP:
                info.TunnelType = "ISATAP";
                break;
            case TUNNEL_TYPE_6TO4:
                info.TunnelType = "6TO4";
                break;
            case TUNNEL_TYPE_DIRECT:
                info.TunnelType = "DIRECT";
                break;
            default:
                info.TunnelType = "Unknown";
                break;
            }

            // Link Speed
            if (adapter->TransmitLinkSpeed < ULONG_MAX && adapter->ReceiveLinkSpeed < ULONG_MAX) {
                if (adapter->TransmitLinkSpeed >= 1000000000) {
                    info.TransmitLinkSpeed = std::to_string(adapter->TransmitLinkSpeed / 1000000000) + " Gbps";
                }
                else {
                    info.TransmitLinkSpeed = std::to_string(adapter->TransmitLinkSpeed / 1000000) + " Mbps";
                }
                if (adapter->ReceiveLinkSpeed >= 1000000000) {
					info.ReceiveLinkSpeed = std::to_string(adapter->ReceiveLinkSpeed / 1000000000) + " Gbps";
				}
                else {
					info.ReceiveLinkSpeed = std::to_string(adapter->ReceiveLinkSpeed / 1000000) + " Mbps";
				}
			}
            else {
				info.TransmitLinkSpeed = "N/A";
				info.ReceiveLinkSpeed = "N/A";
			}

            // Format MAC address
            std::stringstream macStream;
            for (UINT i = 0; i < adapter->PhysicalAddressLength; ++i) {
                if (i > 0) macStream << ":";
                macStream << std::hex << std::setw(2) << std::setfill('0') << (int)adapter->PhysicalAddress[i];
            }
            info.MACAddress = macStream.str();

            // Extract all DNS suffixes
            IP_ADAPTER_DNS_SUFFIX* dnsSuffix = adapter->FirstDnsSuffix;
            while (dnsSuffix != nullptr) {
                info.DNSSuffixes.push_back(dnsSuffix->String);
                dnsSuffix = dnsSuffix->Next;
            }

            // DNS Server Addresses
            IP_ADAPTER_DNS_SERVER_ADDRESS* dnsAddress = adapter->FirstDnsServerAddress;
            while (dnsAddress) {
                SOCKADDR* sa = dnsAddress->Address.lpSockaddr;
                char dnsStr[INET6_ADDRSTRLEN];
                if (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) {
                    inet_ntop(sa->sa_family, &((struct sockaddr_in*)sa)->sin_addr, dnsStr, sizeof(dnsStr));
                    info.DNSAddresses.push_back(dnsStr);
                }
                dnsAddress = dnsAddress->Next;
            }

            // WINS Server Addresses
            IP_ADAPTER_WINS_SERVER_ADDRESS_LH* winsAddress = adapter->FirstWinsServerAddress;
            while (winsAddress) {
				SOCKADDR* sa = winsAddress->Address.lpSockaddr;
				char winsStr[INET6_ADDRSTRLEN];
                if (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) {
					inet_ntop(sa->sa_family, &((struct sockaddr_in*)sa)->sin_addr, winsStr, sizeof(winsStr));
					info.WINSAddresses.push_back(winsStr);
				}
				winsAddress = winsAddress->Next;
			}

            // Gateway Addresses
            IP_ADAPTER_GATEWAY_ADDRESS_LH* gatewayAddress = adapter->FirstGatewayAddress;
            while (gatewayAddress) {
                SOCKADDR* sa = gatewayAddress->Address.lpSockaddr;
                char gwStr[INET6_ADDRSTRLEN];
                if (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) {
                    inet_ntop(sa->sa_family, &((struct sockaddr_in*)sa)->sin_addr, gwStr, sizeof(gwStr));
                    info.GatewayAddresses.push_back(gwStr);
                }
                gatewayAddress = gatewayAddress->Next;
            }

            // Unicast IP Addresses
            IP_ADAPTER_UNICAST_ADDRESS* address = adapter->FirstUnicastAddress;
            while (address) {
                SOCKADDR* sa = address->Address.lpSockaddr;
                char str[INET_ADDRSTRLEN];
                if (sa->sa_family == AF_INET) {
                    inet_ntop(AF_INET, &((struct sockaddr_in*)sa)->sin_addr, str, sizeof(str));
                    info.IPAddresses.push_back(str);
                }
                else if (sa->sa_family == AF_INET6) {
                    inet_ntop(AF_INET6, &((struct sockaddr_in6*)sa)->sin6_addr, str, sizeof(str));
                    info.IPAddresses.push_back(str);
                }
                address = address->Next;
            }

            // Extract DHCPv4 Server Address
            if (adapter->Dhcpv4Server.lpSockaddr != nullptr) {
                char dhcpStr[INET_ADDRSTRLEN]; // Assume IPv4 address
                inet_ntop(AF_INET, &((struct sockaddr_in*)adapter->Dhcpv4Server.lpSockaddr)->sin_addr, dhcpStr, sizeof(dhcpStr));
                info.Dhcpv4Server = dhcpStr;
            }

            // Extract DHCPv6 Server Address
            if (adapter->Dhcpv6Server.lpSockaddr != nullptr) {
                char dhcpv6Str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)adapter->Dhcpv6Server.lpSockaddr)->sin6_addr, dhcpv6Str, sizeof(dhcpv6Str));
                info.Dhcpv6Server = dhcpv6Str;
            }

            // Flags
            info.DdnsEnabled = adapter->Flags & IP_ADAPTER_DDNS_ENABLED ? "True" : "False";
            info.RegisterAdapterSuffix = adapter->Flags & IP_ADAPTER_REGISTER_ADAPTER_SUFFIX ? "True" : "False";
            info.Dhcpv4Enabled = adapter->Flags & IP_ADAPTER_DHCP_ENABLED ? "True" : "False";
            info.ReceiveOnly = adapter->Flags & IP_ADAPTER_RECEIVE_ONLY ? "True" : "False";
            info.NoMulticast = adapter->Flags & IP_ADAPTER_NO_MULTICAST ? "True" : "False";
            info.Ipv6OtherStatefulConfig = adapter->Flags & IP_ADAPTER_IPV6_OTHER_STATEFUL_CONFIG ? "True" : "False";
            info.NetbiosOverTcpipEnabled = adapter->Flags & IP_ADAPTER_NETBIOS_OVER_TCPIP_ENABLED ? "True" : "False";
            info.Ipv4Enabled = adapter->Flags & IP_ADAPTER_IPV4_ENABLED ? "True" : "False";
            info.Ipv6Enabled = adapter->Flags & IP_ADAPTER_IPV6_ENABLED ? "True" : "False";
            info.Ipv6ManagedAddressConfig = adapter->Flags & IP_ADAPTER_IPV6_MANAGE_ADDRESS_CONFIG ? "True" : "False";

            adapters.push_back(info);
            adapter = adapter->Next;
        }
    }
    else {
        std::cerr << "Failed to get adapter addresses. Error: " << ret << std::endl;
    }

    return adapters;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    auto adapters = GetAllAdaptersInfo();
    for (const auto& adapter : adapters) {
        std::wcout << "Adapter Name: " << adapter.Name << std::endl;
        std::wcout << "Adapter Description: " << adapter.Description << std::endl;
        std::cout << "MAC Address: " << adapter.MACAddress << std::endl;
        std::wcout << "DNS Suffix: " << adapter.DNSSuffix << std::endl;
        std::cout << "Operational Status: " << adapter.OperationalStatus << std::endl;
        std::cout << "Adapter Type: " << adapter.AdapterType << std::endl;
        std::cout << "Tunnel Type: " << adapter.TunnelType << std::endl;
        std::cout << "DHCPv4 Server: " << adapter.Dhcpv4Server << std::endl;
        std::cout << "DHCPv6 Server: " << adapter.Dhcpv6Server << std::endl;
        std::cout << "Transmit Link Speed: " << adapter.TransmitLinkSpeed << std::endl;
        std::cout << "Receive Link Speed: " << adapter.ReceiveLinkSpeed << std::endl;
        for (const auto& dnsSuffix : adapter.DNSSuffixes) {
			std::wcout << "Additional DNS Suffix: " << dnsSuffix << std::endl;
		}
        for (const auto& ip : adapter.IPAddresses) {
            std::cout << "IP Address: " << ip << std::endl;
        }
        for (const auto& dns : adapter.DNSAddresses) {
			std::cout << "DNS Server: " << dns << std::endl;
		}
        for (const auto& wins : adapter.WINSAddresses) {
            std::cout << "WINS Server: " << wins << std::endl;
        }
        for (const auto& gw : adapter.GatewayAddresses) {
			std::cout << "Gateway Address: " << gw << std::endl;
		}
        std::cout << "DDNS Enabled: " << adapter.DdnsEnabled << std::endl;
		std::cout << "Register Adapter Suffix: " << adapter.RegisterAdapterSuffix << std::endl;
		std::cout << "DHCPv4 Enabled: " << adapter.Dhcpv4Enabled << std::endl;
		std::cout << "Receive Only: " << adapter.ReceiveOnly << std::endl;
		std::cout << "No Multicast: " << adapter.NoMulticast << std::endl;
		std::cout << "IPv6 Other Stateful Config: " << adapter.Ipv6OtherStatefulConfig << std::endl;
		std::cout << "NetBIOS Over TCP/IP Enabled: " << adapter.NetbiosOverTcpipEnabled << std::endl;
		std::cout << "IPv4 Enabled: " << adapter.Ipv4Enabled << std::endl;
		std::cout << "IPv6 Enabled: " << adapter.Ipv6Enabled << std::endl;
		std::cout << "IPv6 Managed Address Config: " << adapter.Ipv6ManagedAddressConfig << std::endl;
		std::cout << std::endl;
    }

    getchar();

    WSACleanup();
    return 0;
}
