/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 Alexander Afanasyev
 * Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SIMPLE_ROUTER_CORE_UTILS_HPP
#define SIMPLE_ROUTER_CORE_UTILS_HPP

#include "protocol.hpp"

namespace simple_router {

// Validates the integrity of IP packets during forwarding.
uint16_t cksum(const void* data, int len); 

// Extracts the Ethernet type from the Ethernet header
// Determines the type of the next protocol (e.g., IP, ARP) in Ethernet frames
uint16_t ethertype(const uint8_t* buf);

// Extracts the protocol field from the IP header
// Identifies the transport-layer protocol (e.g., ICMP).
uint8_t ip_protocol(const uint8_t* buf);

/**
 * Get formatted Ethernet address, e.g. 00:11:22:33:44:55
 * Convert addresses (e.g., MAC, IP) to human-readable strings
 * Make sure you are passing the IP address in the correct byte ordering
 */
std::string
macToString(const Buffer& macAddr);

std::string
ipToString(uint32_t ip);

std::string
ipToString(const in_addr& address);

// Prints the contents of an Ethernet header (source/destination MACs, type).
void print_hdr_eth(const uint8_t* buf);
// Prints details from the IP header (version, length, TTL, source/destination IP).
void print_hdr_ip(const uint8_t* buf);
// Prints ICMP header fields (type, code, checksum).
void print_hdr_icmp(const uint8_t* buf);
// Prints ARP header fields (sender/target IP and MAC addresses)
void print_hdr_arp(const uint8_t* buf);

/* prints all headers, starting from eth 
   visualize how packets are structured as they pass through the router. */
void print_hdrs(const uint8_t* buf, uint32_t length);

void print_hdrs(const Buffer& buffer);

} // namespace simple_router

#endif // SIMPLE_ROUTER_CORE_UTILS_HPP


/* 

Use print_hdrs() in handlePacket(): 
Add debugging statements to inspect packets as they are received and processed.

IP Packet Validation: 
Use cksum() to validate incoming packets in handlePacket().

ARP Debugging with MAC Conversion:
Use macToString() and print_hdr_eth() for detailed ARP request/response inspection.

IP and ICMP Handling:
Use print_hdr_ip() and print_hdr_icmp() when implementing ICMP responses (e.g., TTL expired, unreachable).

*/