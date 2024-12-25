#include "Win32.hpp"
#include "SecureString.hpp"
#include "SecureWideString.hpp"
#include "SecureException.hpp"
#include "StringCrypt.hpp"
#include "Instance.hpp"
#include "ThreadPool.hpp"
#include <iomanip>
#include <sstream>
#include <iostream>

SecureString NetworkAdapters::sockaddr_to_ip (SOCKADDR* sa) {
	pinet_ntop _pinet_ntop = (pinet_ntop)Win32::WinSockTable.pinet_ntop.pAddress;
	SecureString str(INET6_ADDRSTRLEN);
    if (sa->sa_family == AF_INET) {
		_pinet_ntop(AF_INET, &((struct sockaddr_in*)sa)->sin_addr, str.begin(), str.size());
	}
	else if (sa->sa_family == AF_INET6) {
		_pinet_ntop(AF_INET6, &((struct sockaddr_in6*)sa)->sin6_addr, str.begin(), str.size());
	}
	return str;
}

void NetworkAdapters::processUnicastAddresses(IP_ADAPTER_ADDRESSES* adapter, std::vector<SecureString>& ipAddresses) {
	pinet_ntop _pinet_ntop = (pinet_ntop)Win32::WinSockTable.pinet_ntop.pAddress;

    for (IP_ADAPTER_UNICAST_ADDRESS* addr = adapter->FirstUnicastAddress; addr != NULL; addr = addr->Next) {
        ipAddresses.push_back(sockaddr_to_ip(addr->Address.lpSockaddr));
    }
}

void NetworkAdapters::processDnsServerAddresses(IP_ADAPTER_ADDRESSES* adapter, std::vector<SecureString>& dnsAddresses) {
	pinet_ntop _pinet_ntop = (pinet_ntop)Win32::WinSockTable.pinet_ntop.pAddress;

	for (IP_ADAPTER_DNS_SERVER_ADDRESS* addr = adapter->FirstDnsServerAddress; addr != NULL; addr = addr->Next) {
		dnsAddresses.push_back(sockaddr_to_ip(addr->Address.lpSockaddr));
	}
}

void NetworkAdapters::processGatewayAddresses(IP_ADAPTER_ADDRESSES* adapter, std::vector<SecureString>& gatewayAddresses) {
	pinet_ntop _pinet_ntop = (pinet_ntop)Win32::WinSockTable.pinet_ntop.pAddress;

	for (IP_ADAPTER_GATEWAY_ADDRESS_LH* addr = adapter->FirstGatewayAddress; addr != NULL; addr = addr->Next) {
		gatewayAddresses.push_back(sockaddr_to_ip(addr->Address.lpSockaddr));
	}
}

void NetworkAdapters::processWinsServerAddresses(IP_ADAPTER_ADDRESSES* adapter, std::vector<SecureString>& winsAddresses) {
	pinet_ntop _pinet_ntop = (pinet_ntop)Win32::WinSockTable.pinet_ntop.pAddress;

	for (IP_ADAPTER_WINS_SERVER_ADDRESS_LH* addr = adapter->FirstWinsServerAddress; addr != NULL; addr = addr->Next) {
		winsAddresses.push_back(sockaddr_to_ip(addr->Address.lpSockaddr));
	}
}

void NetworkAdapters::processDnsSuffixes(IP_ADAPTER_ADDRESSES* adapter, std::vector<SecureWideString>& dnsSuffixes) {
    for (IP_ADAPTER_DNS_SUFFIX* suffix = adapter->FirstDnsSuffix; suffix != NULL; suffix = suffix->Next) {
		dnsSuffixes.push_back(SecureWideString(suffix->String));
	}
}

void NetworkAdapters::processOperationalStatus(IP_ADAPTER_ADDRESSES* adapter, AdapterInfo& info) {
    info.OperationalStatus = adapter->OperStatus == IfOperStatusUp ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::UP_CAP_CRYPT)) :
		std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::DOWN_CAP_CRYPT));
}

void NetworkAdapters::processAdapterType(IP_ADAPTER_ADDRESSES* adapter, AdapterInfo& info) {
    switch (adapter->IfType) {
    case IF_TYPE_OTHER:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::OTHER_CAP_CRYPT));
        break;
    case IF_TYPE_ETHERNET_CSMACD:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::ETHERNET_CRYPT));
        break;
    case IF_TYPE_ISO88025_TOKENRING:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TOKENRING_CRYPT));
        break;
    case IF_TYPE_PPP:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::PPP_CRYPT));
        break;
    case IF_TYPE_SOFTWARE_LOOPBACK:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::LOOPBACK_CRYPT));
        break;
    case IF_TYPE_ATM:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::ATM_CRYPT));
        break;
    case IF_TYPE_PROP_VIRTUAL:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::VIRTUAL_VPN_CRYPT));
        break;
    case IF_TYPE_IEEE80211:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::IEEE802_11WIRELESS_CRYPT));
        break;
    case IF_TYPE_TUNNEL:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TUNNEL_CRYPT));
        break;
    case IF_TYPE_IEEE1394:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::IEEE1394_CRYPT));
        break;
    case IF_TYPE_WWANPP:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::WWANPP_CRYPT));
        break;
    case IF_TYPE_WWANPP2:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::WWANPP2_CRYPT));
        break;
    default:
        info.AdapterType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::UNKNOWN_CAP_CRYPT));
        info.AdapterType.get()->append(" (");
        info.AdapterType.get()->append(std::to_string(adapter->IfType).c_str());
        info.AdapterType.get()->append(")");
        break;
    }
}

void NetworkAdapters::processTunnelType(IP_ADAPTER_ADDRESSES* adapter, AdapterInfo& info) {
    switch (adapter->TunnelType) {
    case TUNNEL_TYPE_NONE:
        info.TunnelType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::NONE_CRYPT));
        break;
    case TUNNEL_TYPE_OTHER:
        info.TunnelType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::OTHER_CRYPT));
        break;
    case TUNNEL_TYPE_TEREDO:
        info.TunnelType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TEREDO_CRYPT));
        break;
    case TUNNEL_TYPE_IPHTTPS:
        info.TunnelType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::IPHTTPS_CRYPT));
        break;
    case TUNNEL_TYPE_ISATAP:
        info.TunnelType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::ISATAP_CRYPT));
        break;
    case TUNNEL_TYPE_6TO4:
        info.TunnelType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::SIXTOFOUR_CRYPT));
        break;
    case TUNNEL_TYPE_DIRECT:
        info.TunnelType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::DIRECT_CRYPT));
        break;
    default:
        info.TunnelType = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::UNKNOWN_CRYPT));
        break;
    }
}

void NetworkAdapters::processLinkSpeeds(IP_ADAPTER_ADDRESSES* adapter, AdapterInfo& info) {
    if (adapter->TransmitLinkSpeed < ULONG_MAX && adapter->ReceiveLinkSpeed < ULONG_MAX) {
        if (adapter->TransmitLinkSpeed >= 1000000000) {
            info.TransmitLinkSpeed = std::make_unique<SecureString>();
            info.TransmitLinkSpeed.get()->append(std::to_string(adapter->TransmitLinkSpeed / 1000000000).c_str());
            info.TransmitLinkSpeed.get()->append(StringCrypt::DecryptString(StringCrypt::SPACE_GBPS_CRYPT).c_str());
        }
        else {
            info.TransmitLinkSpeed = std::make_unique<SecureString>();
            info.TransmitLinkSpeed.get()->append(std::to_string(adapter->TransmitLinkSpeed / 1000000).c_str());
            info.TransmitLinkSpeed.get()->append(StringCrypt::DecryptString(StringCrypt::SPACE_MBPS_CRYPT).c_str());
        }
        if (adapter->ReceiveLinkSpeed >= 1000000000) {
            info.ReceiveLinkSpeed = std::make_unique<SecureString>();
            info.ReceiveLinkSpeed.get()->append(std::to_string(adapter->ReceiveLinkSpeed / 1000000000).c_str());
            info.ReceiveLinkSpeed.get()->append(StringCrypt::DecryptString(StringCrypt::SPACE_GBPS_CRYPT).c_str());
        }
        else {
            info.ReceiveLinkSpeed = std::make_unique<SecureString>();
            info.ReceiveLinkSpeed.get()->append(std::to_string(adapter->ReceiveLinkSpeed / 1000000).c_str());
            info.ReceiveLinkSpeed.get()->append(StringCrypt::DecryptString(StringCrypt::SPACE_MBPS_CRYPT).c_str());
        }
    }
    else {
        info.TransmitLinkSpeed = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::N_SLASH_A_CRYPT));
        info.ReceiveLinkSpeed = std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::N_SLASH_A_CRYPT));
    }    
}

void NetworkAdapters::processPhysicalAddress(IP_ADAPTER_ADDRESSES* adapter, AdapterInfo& info) {	
    std::stringstream macStream;
    for (UINT i = 0; i < adapter->PhysicalAddressLength; ++i) {
        if (i > 0) macStream << ":";
        macStream << std::hex << std::setw(2) << std::setfill('0') << (int)adapter->PhysicalAddress[i];
    }
    info.MACAddress = std::make_unique<SecureString>(macStream.str().c_str());
}

void NetworkAdapters::processDhcpServer(IP_ADAPTER_ADDRESSES* adapter, AdapterInfo& info, bool v4) {
    if (v4) {
        if (adapter->Dhcpv4Server.lpSockaddr) {
			info.Dhcpv4Server = std::make_unique<SecureString>(sockaddr_to_ip(adapter->Dhcpv4Server.lpSockaddr));
		}
	}
    else {
        if (adapter->Dhcpv6Server.lpSockaddr) {
			info.Dhcpv6Server = std::make_unique<SecureString>(sockaddr_to_ip(adapter->Dhcpv6Server.lpSockaddr));
		}
	}
}

void NetworkAdapters::processFlags(IP_ADAPTER_ADDRESSES* adapter, AdapterInfo& info) {
    info.DdnsEnabled = adapter->Flags & IP_ADAPTER_DDNS_ENABLED ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.RegisterAdapterSuffix = adapter->Flags & IP_ADAPTER_REGISTER_ADAPTER_SUFFIX ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.Dhcpv4Enabled = adapter->Flags & IP_ADAPTER_DHCP_ENABLED ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.ReceiveOnly = adapter->Flags & IP_ADAPTER_RECEIVE_ONLY ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.NoMulticast = adapter->Flags & IP_ADAPTER_NO_MULTICAST ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.Ipv6OtherStatefulConfig = adapter->Flags & IP_ADAPTER_IPV6_OTHER_STATEFUL_CONFIG ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.NetbiosOverTcpipEnabled = adapter->Flags & IP_ADAPTER_NETBIOS_OVER_TCPIP_ENABLED ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.Ipv4Enabled = adapter->Flags & IP_ADAPTER_IPV4_ENABLED ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.Ipv6Enabled = adapter->Flags & IP_ADAPTER_IPV6_ENABLED ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
    info.Ipv6ManagedAddressConfig = adapter->Flags & IP_ADAPTER_IPV6_MANAGE_ADDRESS_CONFIG ? std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::TRUE_CAP_CRYPT)) :
        std::make_unique<SecureString>(StringCrypt::DecryptString(StringCrypt::FALSE_CAP_CRYPT));
}

bool NetworkAdapters::isValid(const std::unique_ptr<SecureString>& str) {
    if (str.get() == nullptr) {
		return false;
	}
    return !str.get()->empty();
}

bool NetworkAdapters::isValid(const std::unique_ptr<SecureWideString>& str) {
    if (str.get() == nullptr) {
		return false;
	}
	return !str.get()->empty();
}

std::vector<AdapterInfo> NetworkAdapters::GetAllAdaptersInfo() {
    pGetAdaptersAddresses _pGetAdaptersAddresses = (pGetAdaptersAddresses)Win32::IpHlpApiTable.pGetAdaptersAddresses.pAddress;
    pinet_ntop _pinet_ntop = (pinet_ntop)Win32::WinSockTable.pinet_ntop.pAddress;

    ULONG bufferSize = sizeof(IP_ADAPTER_ADDRESSES);
    std::vector<AdapterInfo> adapters;
    std::vector<BYTE> buffer(bufferSize);
    ULONG ret = _pGetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        ret = _pGetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);
    }

    if (ret == NO_ERROR) {
        IP_ADAPTER_ADDRESSES* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        while (adapter) {
            AdapterInfo info;
            // Process wide strings
            info.Name = std::make_unique<SecureWideString>(adapter->FriendlyName);
            info.Description = std::make_unique<SecureWideString>(adapter->Description);
            info.DNSSuffix = std::make_unique<SecureWideString>(adapter->DnsSuffix);
            // Process vectors
            processUnicastAddresses(adapter, info.IPAddresses);
            processDnsServerAddresses(adapter, info.DNSAddresses);
            processGatewayAddresses(adapter, info.GatewayAddresses);
            processWinsServerAddresses(adapter, info.WINSAddresses);
            processDnsSuffixes(adapter, info.DNSSuffixes);
            // Process other fields
            processOperationalStatus(adapter, info);
            processAdapterType(adapter, info);
            processTunnelType(adapter, info);
            processLinkSpeeds(adapter, info);
            processPhysicalAddress(adapter, info);
            processDhcpServer(adapter, info, true);
            processDhcpServer(adapter, info, false);
            // Process flags
            processFlags(adapter, info);

            adapters.push_back(std::move(info));
            adapter = adapter->Next;
        }
        // Debug
        /*for (const auto& adapter : adapters) {
            if (isValid(adapter.Name)) {
				std::wcout << "Adapter Name: " << adapter.Name.get()->c_str() << std::endl;
			}
            if (isValid(adapter.Description)) {
                std::wcout << "Adapter Description: " << adapter.Description.get()->c_str() << std::endl;
            }            
            if (isValid(adapter.MACAddress)) {
                std::cout << "MAC Address: " << adapter.MACAddress.get()->c_str() << std::endl;
            }            
            if (isValid(adapter.DNSSuffix)) {
                std::wcout << "DNS Suffix: " << adapter.DNSSuffix.get()->c_str() << std::endl;
            }            
            if (isValid(adapter.OperationalStatus)) {
				std::cout << "Operational Status: " << adapter.OperationalStatus.get()->c_str() << std::endl;
			}
            if (isValid(adapter.AdapterType)) {
                std::cout << "Adapter Type: " << adapter.AdapterType.get()->c_str() << std::endl;
            }
            if (isValid(adapter.TunnelType)) {
				std::cout << "Tunnel Type: " << adapter.TunnelType.get()->c_str() << std::endl;
			}
            if (isValid(adapter.Dhcpv4Server)) {
				std::cout << "DHCPv4 Server: " << adapter.Dhcpv4Server.get()->c_str() << std::endl;
			}
            if (isValid(adapter.Dhcpv6Server)) {
                std::cout << "DHCPv6 Server: " << adapter.Dhcpv6Server.get()->c_str() << std::endl;
            }
            if (isValid(adapter.TransmitLinkSpeed)) {
				std::cout << "Transmit Link Speed: " << adapter.TransmitLinkSpeed.get()->c_str() << std::endl;
			}
            if (isValid(adapter.ReceiveLinkSpeed)) {
                std::cout << "Receive Link Speed: " << adapter.ReceiveLinkSpeed.get()->c_str() << std::endl;
            }
            for (const auto& dnsSuffix : adapter.DNSSuffixes) {
                if (!dnsSuffix.empty() && dnsSuffix.c_str() != nullptr) {
                    std::wcout << "Additional DNS Suffix: " << dnsSuffix.c_str() << std::endl;
                }                
            }
            for (const auto& ip : adapter.IPAddresses) {
                if (!ip.empty() && ip.c_str() != nullptr) {
                    std::cout << "IP Address: " << ip.c_str() << std::endl;
                }                
            }
            for (const auto& dns : adapter.DNSAddresses) {
                if (!dns.empty() && dns.c_str() != nullptr) {
                    std::cout << "DNS Server: " << dns.c_str() << std::endl;
                }                
            }
            for (const auto& wins : adapter.WINSAddresses) {
                if (!wins.empty() && wins.c_str() != nullptr) {
					std::cout << "WINS Server: " << wins.c_str() << std::endl;
				}
            }
            for (const auto& gw : adapter.GatewayAddresses) {
                if (!gw.empty() && gw.c_str() != nullptr) {
                    std::cout << "Gateway Address: " << gw.c_str() << std::endl;
                }
            }
            if (isValid(adapter.DdnsEnabled)) {
				std::cout << "DDNS Enabled: " << adapter.DdnsEnabled.get()->c_str() << std::endl;
			}
            if (isValid(adapter.RegisterAdapterSuffix)) {
				std::cout << "Register Adapter Suffix: " << adapter.RegisterAdapterSuffix.get()->c_str() << std::endl;
			}
            if (isValid(adapter.Dhcpv4Enabled)) {
                std::cout << "DHCPv4 Enabled: " << adapter.Dhcpv4Enabled.get()->c_str() << std::endl;
            }
            if (isValid(adapter.ReceiveOnly)) {
				std::cout << "Receive Only: " << adapter.ReceiveOnly.get()->c_str() << std::endl;
			}
            if (isValid(adapter.NoMulticast)) {
                std::cout << "No Multicast: " << adapter.NoMulticast.get()->c_str() << std::endl;
            }
            if (isValid(adapter.Ipv6OtherStatefulConfig)) {
                std::cout << "IPv6 Other Stateful Config: " << adapter.Ipv6OtherStatefulConfig.get()->c_str() << std::endl;
            }
            if (isValid(adapter.NetbiosOverTcpipEnabled)) {
				std::cout << "NetBIOS Over TCP/IP Enabled: " << adapter.NetbiosOverTcpipEnabled.get()->c_str() << std::endl;
			}
            if (isValid(adapter.Ipv4Enabled)) {
				std::cout << "IPv4 Enabled: " << adapter.Ipv4Enabled.get()->c_str() << std::endl;
			}
            if (isValid(adapter.Ipv6Enabled)) {
				std::cout << "IPv6 Enabled: " << adapter.Ipv6Enabled.get()->c_str() << std::endl;
			}
            if (isValid(adapter.Ipv6ManagedAddressConfig)) {
				std::cout << "IPv6 Managed Address Config: " << adapter.Ipv6ManagedAddressConfig.get()->c_str() << std::endl;
			}
            std::cout << std::endl;
        }*/
    }
    else {
        throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::GETTINGADAPTERADDRESSES_CRYPT)));
    }

    return adapters;
}

void CALLBACK NetworkAdapters::GetAllAdaptersInfo(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    auto context = reinterpret_cast<SecureTask*>(Context);

    SecureString result;
    SecureString name;
    SecureString description;
    SecureString dnsSuffix;
    std::vector<AdapterInfo> adapters = GetAllAdaptersInfo();

    for (const auto& adapter : adapters) {
        if (isValid(adapter.Name)) {
            name.assign(adapter.Name.get()->begin(), adapter.Name.get()->end());
            result.append(StringCrypt::DecryptString(StringCrypt::ADAPTERNAMECOLON_CRYPT).c_str());
            result.append(name.c_str());
            result.append("\n");
        }
        if (isValid(adapter.Description)) {
            description.assign(adapter.Description.get()->begin(), adapter.Description.get()->end());
			result.append(StringCrypt::DecryptString(StringCrypt::ADAPTERDESCRIPTIONCOLON_CRYPT).c_str());
			result.append(description.c_str());
			result.append("\n");
		}
        if (isValid(adapter.MACAddress)) {
			result.append(StringCrypt::DecryptString(StringCrypt::MACADDRESSCOLON_CRYPT).c_str());
			result.append(adapter.MACAddress.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.DNSSuffix)) {
			dnsSuffix.assign(adapter.DNSSuffix.get()->begin(), adapter.DNSSuffix.get()->end());
            result.append(StringCrypt::DecryptString(StringCrypt::DNSSUFFIXCOLON_CRYPT).c_str());
            result.append(dnsSuffix.c_str());
            result.append("\n");
        }
        if (isValid(adapter.OperationalStatus)) {
            result.append(StringCrypt::DecryptString(StringCrypt::OPERATIONALSTATUSCOLON_CRYPT).c_str());
            result.append(adapter.OperationalStatus.get()->c_str());
            result.append("\n");
        }
        if (isValid(adapter.AdapterType)) {
			result.append(StringCrypt::DecryptString(StringCrypt::ADAPTERTYPECOLON_CRYPT).c_str());
			result.append(adapter.AdapterType.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.TunnelType)) {
            result.append(StringCrypt::DecryptString(StringCrypt::TUNNELTYPECOLON_CRYPT).c_str());
            result.append(adapter.TunnelType.get()->c_str());
            result.append("\n");
        }
        if (isValid(adapter.Dhcpv4Server)) {
			result.append(StringCrypt::DecryptString(StringCrypt::DHCPV4SERVERCOLON_CRYPT).c_str());
			result.append(adapter.Dhcpv4Server.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.Dhcpv6Server)) {
			result.append(StringCrypt::DecryptString(StringCrypt::DHCPV6SERVERCOLON_CRYPT).c_str());
			result.append(adapter.Dhcpv6Server.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.TransmitLinkSpeed)) {
            result.append(StringCrypt::DecryptString(StringCrypt::TRANSMITLINKSPEEDCOLON_CRYPT).c_str());
            result.append(adapter.TransmitLinkSpeed.get()->c_str());
            result.append("\n");
        }
        if (isValid(adapter.ReceiveLinkSpeed)) {
			result.append(StringCrypt::DecryptString(StringCrypt::RECEIVELINKSPEEDCOLON_CRYPT).c_str());
			result.append(adapter.ReceiveLinkSpeed.get()->c_str());
			result.append("\n");
		}
        for (const auto& dnsSuffix : adapter.DNSSuffixes) {
            if (!dnsSuffix.empty() && dnsSuffix.c_str() != nullptr) {
                SecureString dnsSuffix;
                dnsSuffix.assign(dnsSuffix.begin(), dnsSuffix.end());
				result.append(StringCrypt::DecryptString(StringCrypt::ADDITIONALDNSSUFFIXCOLON_CRYPT).c_str());
				result.append(dnsSuffix.c_str());
				result.append("\n");
			}
		}
        for (const auto& ip : adapter.IPAddresses) {
            if (!ip.empty() && ip.c_str() != nullptr) {
				result.append(StringCrypt::DecryptString(StringCrypt::IPADDRESSCOLON_CRYPT).c_str());
				result.append(ip.c_str());
				result.append("\n");
			}
		}
        for (const auto& dns : adapter.DNSAddresses) {
            if (!dns.empty() && dns.c_str() != nullptr) {
				result.append(StringCrypt::DecryptString(StringCrypt::DNSSERVERCOLON_CRYPT).c_str());
				result.append(dns.c_str());
				result.append("\n");
			}
		}
        for (const auto& wins : adapter.WINSAddresses) {
            if (!wins.empty() && wins.c_str() != nullptr) {
				result.append(StringCrypt::DecryptString(StringCrypt::WINSSERVERCOLON_CRYPT).c_str());
				result.append(wins.c_str());
				result.append("\n");
			}
		}
        for (const auto& gw : adapter.GatewayAddresses) {
            if (!gw.empty() && gw.c_str() != nullptr) {
				result.append(StringCrypt::DecryptString(StringCrypt::GATEWAYADDRESSCOLON_CRYPT).c_str());
				result.append(gw.c_str());
				result.append("\n");
			}
		}
        if (isValid(adapter.DdnsEnabled)) {
			result.append(StringCrypt::DecryptString(StringCrypt::DDNSENABLEDCOLON_CRYPT).c_str());
			result.append(adapter.DdnsEnabled.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.RegisterAdapterSuffix)) {
			result.append(StringCrypt::DecryptString(StringCrypt::REGISTERADAPTERSUFFIXCOLON_CRYPT).c_str());
			result.append(adapter.RegisterAdapterSuffix.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.Dhcpv4Enabled)) {
            result.append(StringCrypt::DecryptString(StringCrypt::DHCPV4ENABLEDCOLON_CRYPT).c_str());
            result.append(adapter.Dhcpv4Enabled.get()->c_str());
            result.append("\n");
        }
        if (isValid(adapter.ReceiveOnly)) {
            result.append(StringCrypt::DecryptString(StringCrypt::RECEIVEONLYCOLON_CRYPT).c_str());
            result.append(adapter.ReceiveOnly.get()->c_str());
            result.append("\n");
        }
        if (isValid(adapter.NoMulticast)) {
			result.append(StringCrypt::DecryptString(StringCrypt::NOMULTICASTCOLON_CRYPT).c_str());
			result.append(adapter.NoMulticast.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.Ipv6OtherStatefulConfig)) {
			result.append(StringCrypt::DecryptString(StringCrypt::IPV6OTHERSTATEFULCONFIGCOLON_CRYPT).c_str());
			result.append(adapter.Ipv6OtherStatefulConfig.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.NetbiosOverTcpipEnabled)) {
            result.append(StringCrypt::DecryptString(StringCrypt::NETBIOSOVERTCPIPENABLEDCOLON_CRYPT).c_str());
            result.append(adapter.NetbiosOverTcpipEnabled.get()->c_str());
            result.append("\n");
        }
        if (isValid(adapter.Ipv4Enabled)) {
            result.append(StringCrypt::DecryptString(StringCrypt::IPV4ENABLEDCOLON_CRYPT).c_str());
            result.append(adapter.Ipv4Enabled.get()->c_str());
            result.append("\n");
        }
        if (isValid(adapter.Ipv6Enabled)) {
			result.append(StringCrypt::DecryptString(StringCrypt::IPV6ENABLEDCOLON_CRYPT).c_str());
			result.append(adapter.Ipv6Enabled.get()->c_str());
			result.append("\n");
		}
        if (isValid(adapter.Ipv6ManagedAddressConfig)) {
            result.append(StringCrypt::DecryptString(StringCrypt::IPV6MANAGEDADDRESSCONFIGCOLON_CRYPT).c_str());
            result.append(adapter.Ipv6ManagedAddressConfig.get()->c_str());
            result.append("\n");
        }
        result.append("\n");
    }

    SyscallPrepare(SystemCalls::SysTable.SysNtSetEvent.wSyscallNr, SystemCalls::SysTable.SysNtSetEvent.pRecycled);
    Instance::NtStatus = SysNtSetEvent(context->CompletionEvent, NULL);
    context->Result = std::make_unique<SecureString>(result);
    context->Success = true;
}