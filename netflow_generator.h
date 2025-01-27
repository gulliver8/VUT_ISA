//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $flow $netflow_generator.h
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        netflow_generator.h
 * @author      Lucia Makaiová
 *
 * @brief       Specifies netflow structures for header, flow and key for mapping
 */

#ifndef PROJEKT_NETFLOW_GENERATOR_H
#define PROJEKT_NETFLOW_GENERATOR_H

#include "arguments.h"
//structure for netflow header
struct Netflow_hdr{
    uint16_t version;           //NetFlow export format version number
    uint16_t count;	            //Number of flows that are exported in this packet (1-30)
    uint32_t sys_uptime;        //Current time in milliseconds since the export device started
    uint32_t unix_secs;	        //Current count of seconds since 0000 Coordinated Universal Time 1970
    uint32_t unix_nsecs;	    //Residual nanoseconds since 0000 Coordinated Universal Time 1970
    uint32_t flow_sequence;	    //Sequence counter of total flows seen
    uint8_t engine_type;	    //Type of flow-switching engine
    uint8_t engine_id;	        //Slot number of the flow-switching engine
    uint16_t sampling_interval; //First 2b -sampling mode; remaining 14b -sampling interval
};
//structure to store netflow flow records
struct Netflow{
    uint32_t srcaddr;	    //Source IP address
    uint32_t dstaddr;	    //Destination IP address
    uint32_t nexthop;	    //IP address of next hop router
    uint16_t input;	        //SNMP index of input interface
    uint16_t output; 	    //SNMP index of output interface
    uint32_t dPkts;	        //Packets in the flow
    uint32_t dOctets;	    //Total number of Layer 3 bytes in the packets of the flow
    uint32_t First;	        //SysUptime at start of flow
    uint32_t Last;	        //SysUptime at the time the last packet of the flow was received
    uint16_t srcport;	    //TCP/UDP source port number or equivalent
    uint16_t dstport;	    //TCP/UDP destination port number or equivalent
    uint8_t pad1;	        //Unused (zero) byte
    uint8_t tcp_flags;	    //Cumulative OR of TCP flags
    uint8_t prot;	        //IP protocol type (for example, TCP = 6; UDP = 17)
    uint8_t	IP;             //type of service (ToS)
    uint16_t src_as;	    //Autonomous system number of the source, either origin or peer
    uint16_t dst_as;	    //Autonomous system number of the destination, either origin or peer
    uint8_t src_mask;	    //Source address prefix mask bits
    uint8_t dst_mask;	    //Destination address prefix mask bits
    uint16_t  pad2;	        //Unused (zero) bytes
};
//structure for key for mapping netflows
struct Netflow_base{
    uint32_t srcaddr;	    //Source IP address
    uint32_t dstaddr;	    //Destination IP address
    uint16_t srcport;	    //TCP/UDP source port number or equivalent
    uint16_t dstport;	    //TCP/UDP destination port number or equivalen
    uint8_t prot;	        //IP protocol type (for example, TCP = 6; UDP = 17
    //custom comparison operator
    bool operator<(const Netflow_base& other) const{
        if (srcaddr + 2*dstaddr + srcport + 2*dstport + prot <
            other.srcaddr + 2*other.dstaddr + other.srcport +2*other.dstport + other.prot) {
            return  true;
        }
        return false;
    }
    //custom equality operator (dstaddr and port multiplied by to do differ between bidirectional communication)
    bool operator==(const Netflow_base& other) const{
        if (srcaddr + 2*dstaddr + srcport + 2*dstport + prot ==
            other.srcaddr + 2*other.dstaddr + other.srcport +2*other.dstport + other.prot) {
            return  true;
        }
        return false;
    }
};

int client(Options options);    //create udp client

#endif //PROJEKT_NETFLOW_GENERATOR_H
