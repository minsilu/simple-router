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

#include "interface.hpp"
#include "core/utils.hpp"

namespace simple_router {

Interface::Interface(const std::string& name, const Buffer& addr, uint32_t ip)
  : name(name) // The name of the network interface (e.g., "eth0").
  , addr(addr) // The MAC address of the interface, stored as a binary buffer.
  , ip(ip) // The IP address of the interface, stored as a 32-bit integer.
{
}

// Example output: eth0 (192.168.1.1, 00:0c:29:02:39:28)
std::ostream&
operator<<(std::ostream& os, const Interface& iface)
{
  os << iface.name
     << " (" << ipToString(iface.ip)
     << ", " << macToString(iface.addr) << ")";
  return os;
}

} // namespace simple_router


/*
When the router initializes (e.g., in SimpleRouter::reset()), 
the Interface class is used to represent and store each network adapter's details.

When a packet is received or sent, the SimpleRouter class uses 
the Interface objects to determine which network adapter is involved 
(via methods like findIfaceByName or findIfaceByIp)

The routing table and ARP cache interact with Interface objects
 to resolve addresses and send packets to the correct destination.

*/