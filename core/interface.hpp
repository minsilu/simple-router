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

#ifndef SIMPLE_ROUTER_INTERFACE_HPP
#define SIMPLE_ROUTER_INTERFACE_HPP

#include "protocol.hpp"

#include <ostream>

namespace simple_router {

/**
 * Network interface abstraction
 */
class Interface
{
public:
  Interface(const std::string& name, const Buffer& addr, uint32_t ip);

  void
  print();

  bool
  operator<(const Interface& rh) const; // It compares interfaces by their name

public:
  std::string name;
  Buffer addr;
  uint32_t ip;
};

inline bool
Interface::operator<(const Interface& rh) const
{
  return name < rh.name;
}

// Overloaded to allow easy printing of Interface objects. 
// It formats and outputs the name, IP, and MAC address of the interface.
std::ostream&
operator<<(std::ostream& os, const Interface& iface); 

} // namespace simple_router

#endif // SIMPLE_ROUTER_INTERFACE_HPP


/*
When the router initializes (e.g., in SimpleRouter::reset()), 
the Interface class is used to represent and store each network adapter's details.

When a packet is received or sent, the SimpleRouter class uses 
the Interface objects to determine which network adapter is involved 
(via methods like findIfaceByName or findIfaceByIp)

The routing table and ARP cache interact with Interface objects
 to resolve addresses and send packets to the correct destination.

*/