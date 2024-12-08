/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {



void SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface) {
    std::cout << "[INFO] Received a packet of size " << packet.size()
              << " bytes on interface '" << inIface << "'" << std::endl;

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "[WARNING] Unknown interface '" << inIface << "'. Packet ignored." << std::endl;
        return;
    }

    // Output the routing table for debugging purposes
    std::cout << "[DEBUG] Current Routing Table:\n" << getRoutingTable() << std::endl;

    // Verify that the packet contains at least an Ethernet header
    if (packet.size() < sizeof(ethernet_hdr)) {
        std::cerr << "[ERROR] Packet too short to contain a valid Ethernet header. Ignoring." << std::endl;
        return;
    }

    // Extract and identify the EtherType from the Ethernet header
    const ethernet_hdr* ethHeader = reinterpret_cast<const ethernet_hdr*>(packet.data());
    uint16_t ethType = ntohs(ethHeader->ether_type);

    if (ethType != ethertype_ip && ethType != ethertype_arp) {
        std::cerr << "[INFO] Unsupported EtherType: 0x" << std::hex << ethType << std::dec << ". Ignoring packet." << std::endl;
        return;
    }

    // Validate the destination MAC address
    bool isDirectedToRouter = std::memcmp(ethHeader->ether_dhost, iface->addr.data(), ETHER_ADDR_LEN) == 0;
    bool isBroadcast = std::all_of(ethHeader->ether_dhost, ethHeader->ether_dhost + ETHER_ADDR_LEN, [](uint8_t a) { return a == 0xff; });

    if (isDirectedToRouter) {
        std::cout << "[INFO] Packet is addressed to the router's interface MAC address." << std::endl;
    }
    else if (isBroadcast) {
        std::cout << "[INFO] Packet is a broadcast frame." << std::endl;
    }
    else {
        std::cerr << "[INFO] Destination MAC address does not match router's interface or broadcast. Ignoring packet." << std::endl;
        return;
    }

    // Delegate packet processing based on EtherType
    if (ethType == ethertype_arp) {
        handleArp(packet, inIface);  // Handle ARP packet
    } 
    else if (ethType == ethertype_ip) {
        handleIPv4(packet, inIface); // Handle IPv4 packet
    } 
}

void SimpleRouter::handleArp(const Buffer& packet, const std::string& inIface) {
    std::cout << "[ACTION] Processing ARP packet on interface '" << inIface << "'." << std::endl;

    const size_t arp_packet_size = sizeof(ethernet_hdr) + sizeof(arp_hdr);
    if (packet.size() != arp_packet_size) {
        std::cerr << "[ERROR] Packet size (" << packet.size() << " bytes) is no equal to ARP packet size (" 
                  << arp_packet_size << " bytes). Discarding packet." << std::endl;
        return;
    }

    // Locate the ARP header within the packet
    const arp_hdr* arpHeader = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));

    // Validate the ARP hardware type (should be Ethernet)
    if (ntohs(arpHeader->arp_hrd) != arp_hrd_ethernet) {
        std::cerr << "[WARNING] Unsupported ARP hardware type (" << hwType << "). Expected Ethernet (" 
                  << arp_hrd_ethernet << "). Ignoring packet." << std::endl;
        return;
    }

    // Validate the ARP protocol type (should be IPv4)
    if (ntohs(arpHeader->arp_pro) != ethertype_ip) {
        std::cerr << "[WARNING] Unsupported ARP protocol type (0x" << std::hex << protoType 
                  << "). Expected IPv4 (0x0800). Ignoring packet." << std::endl;
        return;
    }

    // Confirm hardware address length is 6 bytes (Ethernet MAC)
    if (arpHeader->arp_hln != ETHER_ADDR_LEN) {
        std::cerr << "[WARNING] Invalid hardware address length (" << static_cast<int>(arpHeader->arp_hln) 
                  << "). Expected " << ETHER_ADDR_LEN << " bytes. Ignoring packet." << std::endl;
        return;
    }

    // Confirm protocol address length is 4 bytes (IPv4)
    if (arpHeader->arp_pln != IP_ADDR_LEN) {
        std::cerr << "[WARNING] Invalid protocol address length (" << static_cast<int>(arpHeader->arp_pln) 
                  << "). Expected " << IP_ADDR_LEN << " bytes. Ignoring packet." << std::endl;
        return;
    }

    // Determine the ARP operation (request or reply)
    uint16_t arpOp = ntohs(arpHeader->arp_op);
    switch (arpOp) {
        case arp_op_request:
            std::cout << "[INFO] Received ARP Request." << std::endl;
            handleArpRequest(packet, inIface);
            break;
        case arp_op_reply:
            std::cout << "[INFO] Received ARP Reply." << std::endl;
            handleArpReply(packet, inIface);
            break;
        default:
            std::cerr << "[WARNING] Unsupported ARP operation (" << arpOp << "). Only Requests and Replies are handled. Ignoring packet." << std::endl;
            break;
    }
}

void SimpleRouter::handleArpRequest(const Buffer& packet, const std::string& inIface) {
  // Log the reception of an ARP request
  std::cout << "[INFO] Handling ARP Request on interface '" << inIface << "'." << std::endl;

  // Extract Ethernet and ARP headers from the packet
  const ethernet_hdr* eth_ptr = reinterpret_cast<const ethernet_hdr*>(packet.data());
  const arp_hdr* arp_ptr = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));

  const Interface* iface = findIfaceByName(inIface);
  // Validate that the ARP request is targeted at this router's IP address
  if (arp_ptr->arp_tip != iface->ip) { // TDOO: check if arp_ptr->arp_tip != iface->ip
      std::cout << "[INFO] ARP request target IP (" << ntohl(arp_ptr->arp_tip) << ") does not match interface IP (" << iface->ip << "). Ignoring request." << std::endl;
      return;
  }

  // Create a reply buffer by copying the incoming packet
  Buffer reply(packet);
  ethernet_hdr* rep_eth = reinterpret_cast<ethernet_hdr*>(reply.data());
  arp_hdr* rep_arp = reinterpret_cast<arp_hdr*>(reply.data() + sizeof(ethernet_hdr));

  // Modify the Ethernet header for the ARP reply
  std::memcpy(rep_eth->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
  std::memcpy(rep_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN);
  rep_eth->ether_type = htons(ethertype_arp);

  // Modify the ARP header for the reply
  rep_arp->arp_hrd = htons(arp_hrd_ethernet);     // Hardware type: Ethernet
  rep_arp->arp_pro = htons(arp_pro_ip);               // Protocol type: IPv4
  rep_arp->arp_hln = ETHER_ADDR_LEN;              // Hardware address length: 6 bytes
  rep_arp->arp_pln = IP_ADDR_LEN;                 // Protocol address length: 4 bytes
  rep_arp->arp_op  = htons(arp_op_reply);         // Operation: ARP Reply
  rep_arp->arp_sip = iface->ip;                   // Sender IP: Router's IP
  rep_arp->arp_tip = arp_ptr->arp_sip;            // Target IP: Original requester's IP


  std::memcpy(rep_arp->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
  std::memcpy(rep_arp->arp_tha, arp_ptr->arp_sha, ETHER_ADDR_LEN);

  // Log the crafting of the ARP reply
  std::cout << "[INFO] ARP reply crafted successfully. Sending reply." << std::endl;

  // Send the ARP reply back through the same interface
  sendPacket(reply, inIface);
}

void SimpleRouter::handleArpReply(const Buffer& packet, const std::string& inIface) {
    std::cout << "[INFO] Handling ARP Reply on interface '" << inIface << "'." << std::endl;

    const arp_hdr* arp_ptr = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));
    uint32_t sender_ip = arp_ptr->arp_sip;
    Buffer sender_mac(reinterpret_cast<const uint8_t*>(arp_ptr->arp_sha), reinterpret_cast<const uint8_t*>(arp_ptr->arp_sha) + ETHER_ADDR_LEN);

    // std::cout << "[DEBUG] Received ARP Reply: Sender IP = " << sender_ip << ", Sender MAC = " << sender_mac.toString() << std::endl;

    // Update ARP cache and forward any queued requests
    if (!m_arp.lookup(sender_ip)) {
        auto arp_req = m_arp.insertArpEntry(sender_mac, sender_ip);

        if (arp_req) {
            std::cout << "[INFO] Handling queued packets for IP: " << sender_ip << " and MAC: " << macToString(sender_mac) << "." << std::endl;
            for (const auto& queued_pkt : arp_req->packets) {
                handlePacket(queued_pkt.packet, queued_pkt.iface);
            }
            m_arp.removeRequest(arp_req);
        } else {
            std::cout << "[INFO] No queued requests for IP: " << sender_ip << " and MAC: " << macToString(sender_mac) << "." << std::endl;
        }
    } else {
        std::cout << "[INFO] ARP cache already contains IP: " << sender_ip << ". Ignoring reply." << std::endl;
    }
}

void SimpleRouter::handleIPv4(const Buffer& packet, const std::string& inIface){
    std::cout << "[INFO] Handling IPv4 packet on interface '" << inIface << "'." << std::endl;

    // Ensure the packet is large enough to contain Ethernet and IPv4 headers
    if(packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)){
        std::cout << "[ERROR] Packet size (" << packet.size() 
                  << " bytes) is smaller than expected for Ethernet and IP headers. Ignoring." << std::endl;
        return;
    }

    // Extract the IPv4 header 
    ip_hdr* ip_ptr = reinterpret_cast<ip_hdr*>(packet.data() + sizeof(ethernet_hdr));

    // Validate the IPv4 header checksum
    if(cksum(ip_ptr, sizeof(ip_hdr)) != 0xffff){
        std::cout << "[ERROR] IP header checksum is invalid (" << std::hex << computed_checksum 
                  << " != 0xffff). Ignoring." << std::endl;
        return;
    }

    // Extract source and destination IP addresses (convert from network byte order to host byte order)
    // uint32_t src_ip = ip_ptr->ip_src; //ntohl(ip_ptr->ip_src);
    // uint32_t dst_ip = ip_ptr->ip_dst; //ntohl(ip_ptr->ip_dst);

    // // Log source and destination IP addresses
    // std::cout << "[DEBUG] IP Packet: " << src_ip << " -> " << dst_ip 
    //           << ", Protocol: " << static_cast<int>(ip_ptr->ip_p) 
    //           << ", TTL: " << static_cast<int>(ip_ptr->ip_ttl) << std::endl;

    // Determine if the packet is destined for the router
    const Interface* destIface = findIfaceByIp(ip_ptr->ip_dst);
    if (destIface != nullptr) { //  To the router
        std::cout << "[INFO] IP packet destined to the router." << std::endl;
        
        switch(ip_ptr->ip_p){
            case ip_protocol_icmp:
                std::cout << "[INFO] Handling ICMP packet." << std::endl;
                handleICMPEcho(packet, inIface);
                break;
            case ip_protocol_tcp:
            case ip_protocol_udp:
                std::cout << "[INFO] Protocol (" << static_cast<int>(ip_ptr->ip_p) 
                          << ") unsupported. Sending ICMP Port Unreachable." << std::endl;
                handleICMPPortUnreachable(packet, inIface);
                break;
            default:
                std::cout << "[WARNING] Unsupported protocol (" << static_cast<int>(ip_ptr->ip_p) 
                          << "), ignoring packet." << std::endl;
                break;
        }
    } else { // To be forwarded
        std::cout << "[INFO] IP packet to be forwarded." << std::endl;
        
        // Check and decrement TTL
        if(ip_ptr->ip_ttl <= 1){
            std::cout << "[INFO] TTL expired (" << static_cast<int>(ip_ptr->ip_ttl) 
                      << ")" << std::endl;
            handleICMPTimeExceeded(packet, inIface);
        }
        else{
            // Decrement TTL
            ip_ptr->ip_ttl -= 1;
            std::cout << "[INFO] Forwarding IP packet. New TTL: " << static_cast<int>(ip_ptr->ip_ttl) << std::endl;
            forwardIPv4(packet, inIface);
        }
    }
}

void SimpleRouter::handleICMPEcho(const Buffer& packet, const std::string& inIface) {
    std::cout << "[INFO] Processing ICMP Echo or Echo Reply message." << std::endl;

    // Define offsets for Ethernet, IP, and ICMP headers 
    size_t ethernet_offset = 0;
    size_t ip_offset = ethernet_offset + sizeof(ethernet_hdr);
    size_t icmp_offset = ip_offset + sizeof(ip_hdr);

    // Ensure packet size is sufficient
    if(packet.size() < icmp_offset + sizeof(icmp_hdr)) {
        std::cout << "[ERROR] Packet size insufficient for ICMP header. Ignoring." << std::endl;
        return;
    }

    icmp_hdr* icmp_ptr = reinterpret_cast<icmp_hdr*>(packet.data() + icmp_offset);
    // type check
    if(icmp_ptr->icmp_type != icmp_echo || icmp_ptr->icmp_type != icmp_echo_rely){
        std::cout << "ICMP type is not Echo Request (" << static_cast<int>(icmp_ptr->icmp_type) 
                  << "), ignoring." << std::endl;
        return;
    }
    // checksum
    if (cksum(reinterpret_cast<uint8_t*>(icmp_ptr), packet.size() - icmp_offset) != 0xffff) {
        std::cout << "ICMP header checksum is invalid (" << std::hex << computed_checksum 
                  << " != 0xffff), ignoring." << std::endl;
        return;
    }

    ethernet_hdr* eth_ptr = reinterpret_cast<ethernet_hdr*>(packet.data() + ethernet_offset);
    ip_hdr* ip_ptr = reinterpret_cast<ip_hdr*>(packet.data() + ip_offset);
    
    Buffer reply(packet);
    // 1. Construct Ethernet Header
    ethernet_hdr* reply_eth = reinterpret_cast<ethernet_hdr*>(reply.data() + ethernet_offset);
    std::memcpy(reply_eth->ether_dhost, eth_ptr->ether_shost, ETHER_ADDR_LEN); 
    std::memcpy(reply_eth->ether_shost, eth_ptr->ether_dhost, ETHER_ADDR_LEN); 
    reply_eth->ether_type = eth_ptr->ether_type; 

    // 2. Construct IP Header 
    ip_hdr* reply_ip = reinterpret_cast<ethernet_hdr*>(reply.data() + ip_offset);
    reply_ip->ip_id = 0;
    reply_ip->ip_src = ip_ptr->ip_dst; 
    reply_ip->ip_dst = ip_ptr->ip_src; 
    reply_ip->ip_ttl = 64; 
    reply_ip->ip_sum = 0; 
    reply_ip->ip_sum = cksum(reinterpret_cast<uint8_t*>(reply_ip), sizeof(ip_hdr));

    // 3. Construct ICMP Header 
    icmp_hdr* reply_icmp = reinterpret_cast<ethernet_hdr*>(reply.data() + icmp_offset);
    reply_icmp.icmp_type = icmp_echo_rely;
    reply_icmp.icmp_code = 0x00; 
    reply_icmp.icmp_sum = 0; 
    reply_icmp.icmp_sum = cksum(reinterpret_cast<uint8_t*>(reply_icmp), packet.size() - icmp_offset);


    sendPacket(reply_packet, inIface);

    std::cout << "[INFO] ICMP Echo Reply sent." << std::endl;
}



void SimpleRouter::forwardIPv4(const Buffer& packet, const std::string& inIface) {
    std::cout << "Forwarding IPv4 packet" << std::endl;

    ip_hdr* ip_ptr = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));
    
    // Look up the destination IP in the routing table
    auto routing_entry = m_routingTable.lookup(ip_ptr->ip_dst);
    
    // Look up the corresponding ARP entry for the next-hop MAC address
    auto arp_entry = m_arp.lookup(ip_ptr->ip_dst);
    if (arp_entry == nullptr) {
        std::cout << "No ARP entry for destination IP, sending ARP request." << std::endl;
        sendArpRequest(ip_ptr->ip_dst); // Send an ARP request to resolve the MAC address
        return;
    }

    // Get the output interface from the routing table entry
    const Interface* outIface = findIfaceByName(routing_entry.ifName);
    
    // Create a new buffer for the forwarded packet
    Buffer forward(packet);

    // Ethernet header: set the destination MAC address from the ARP cache
    ethernet_hdr* fwd_eth = (ethernet_hdr*)forward.data();
    std::memcpy(fwd_eth->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
    std::memcpy(fwd_eth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);

    // IP header: decrement TTL and recompute the checksum
    ip_hdr* fwd_ip = (ip_hdr*)(forward.data() + sizeof(ethernet_hdr));
    fwd_ip->ip_ttl--;
    fwd_ip->ip_sum = 0;  // Reset checksum
    fwd_ip->ip_sum = cksum((uint8_t*)fwd_ip, sizeof(ip_hdr));  // Recompute checksum

    // Send the packet out the appropriate interface
    sendPacket(forward, routing_entry.ifName);
}


///////////////////////////////////////////////////////////////////////////////////
// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
