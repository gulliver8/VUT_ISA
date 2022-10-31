//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $flow $flow.cpp
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        netflow.cpp
 * @author      Lucia Makaiová
 *
 * @brief
 */


#include "flow.h"
#include <map>
#include <iostream>

struct ether_header *ether_packet;
struct ip *ipv4_packet;
struct ip6_hdr *ipv6_packet;
char src_ip6[128];
char dst_ip6[128];
struct ether_arp *arp_packet;

#define IPV4 0x0800
#define ARP 0x0806
#define IPV6 0x86dd
#define ICMP 1
#define TCP 6
#define UDP 17


using namespace std;
tuple<uint32_t,uint32_t,uint16_t,uint16_t,uint8_t>netflow_base;

map<Netflow_base, Netflow> netflowMap;

void export_all();
void check_timers(int atimer, int iatimer, uint32_t current);
void export_flow(Netflow_base netflow);
void check_cache(uint32_t count);

int main(int argc, char **argv) {
    char err_buf[PCAP_ERRBUF_SIZE]; //control buffer for pcap functions
    int input;
    int protocol;

    ////get program options
    Options options = {60,10,1024,"127.0.0.1:2055","-"};
    get_options(argc, argv, &options);


    //// open pcap session
    pcap_t *session = NULL;
    session = pcap_open_offline(options.source.c_str(), err_buf);
    if (session == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", options.source.c_str(), err_buf);
        exit(FAILURE);
    }

    ////compile filter expression
    //MODIFICATED from
    //SOURCE: https://www.tcpdump.org/pcap.html
    //AUTHOR: The Tcpdump Group
    //COPYRIGHT: Copyright 2002 Tim Carstens
    struct bpf_program compiled_filter;
    if(pcap_compile(session, &compiled_filter, "tcp or udp or icmp", 0,0) == -1){
        fprintf(stderr, "Can't compile filter expression\n");
        exit(FAILURE);
    }

    //set filter to compiled expression
    if(pcap_setfilter(session, &compiled_filter) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(session));
        exit(FAILURE);
    }else{
        //printf("Filter expression:%s applied successfully.",filter_exp);
    }

    struct pcap_pkthdr packet_header; //contains packet timestamp and caplen -length of frame in bytes
    const u_char *packet;

    //packet time values
    int i = 0;
    uint32_t boot_time;
    uint32_t current_time;


    for(packet = pcap_next(session, &packet_header);packet != NULL; packet = pcap_next(session, &packet_header),i++){
        Netflow_base netflow = {};
        Netflow netflow_data = {};
        ////Packet time values
        if(i == 0){
            boot_time =(packet_header.ts.tv_sec * 1000)+(packet_header.ts.tv_usec / 1000);
            printf("saved time %u", boot_time);
        }
        current_time = (packet_header.ts.tv_sec * 1000)+(packet_header.ts.tv_usec / 1000) - boot_time;
        printf("Current %u  \n", current_time);

        ////resolve IP or ICMP port
        ether_packet = (struct ether_header *) packet;

        packet = packet + 14; //cut the ethernet (datalink) header (14 bytes length)

        ////resolve IP dest, source, header size and tos
        if(ntohs(ether_packet->ether_type) == ARP){
            arp_packet = (struct ether_arp *) packet;
            netflow.srcaddr = *arp_packet->arp_spa;
            printf("Src: %u",netflow.srcaddr);
            netflow.dstaddr = *arp_packet->arp_tpa;
            printf("Dst: %u\n",netflow.srcaddr);
            netflow.prot = arp_packet->ea_hdr.ar_pro;
            //printf("src IP: %d.%d.%d.%d\n", arp_packet->arp_spa[0], arp_packet->arp_spa[1], arp_packet->arp_spa[2],arp_packet->arp_spa[3]);
            //printf("dst IP: %d.%d.%d.%d\n", arp_packet->arp_tpa[0], arp_packet->arp_tpa[1], arp_packet->arp_tpa[2],arp_packet->arp_tpa[3]);
            printf("TAKETO");
        }else if(ntohs(ether_packet->ether_type) == IPV4){
            ipv4_packet = (struct ip *) packet;
            netflow.srcaddr = ipv4_packet->ip_src.s_addr;
            printf("Src: %u",netflow.srcaddr);
            netflow.dstaddr = ipv4_packet->ip_dst.s_addr;
            printf("Dst: %u\n",netflow.dstaddr);
            //printf("src IP: %s\n", inet_ntoa(ipv4_packet->ip_src));
            //printf("dst IP: %s\n", inet_ntoa(ipv4_packet->ip_dst));
            protocol = ipv4_packet->ip_p;
            netflow.prot = ipv4_packet->ip_p;
            netflow_data.dOctets = ipv4_packet->ip_hl;
            netflow_data.IP = ipv4_packet->ip_tos;
            packet = packet + 4 * ipv4_packet->ip_hl;
        }else{
            ////TODO: ipv6 packets suipport or not?
        }

        ////TCP, UDP, ICMP support
        if (protocol != ICMP) {
            if (protocol == UDP) {
                struct udphdr *udp_packet;
                udp_packet = (struct udphdr *) packet;
                netflow.srcport = htons(udp_packet->source);
                printf("Src: %u", netflow.srcport);
                netflow.dstport = htons(udp_packet->dest);
                printf("Dst: %u\n", netflow.dstport);
                //printf("src port: %hu\n", htons(udp_packet->uh_sport));
                //printf("dst port: %hu\n", htons(udp_packet->uh_dport));
            } else if (protocol == TCP) {
                struct tcphdr *tcp_packet;

                tcp_packet = (struct tcphdr *) packet;
                netflow.srcport = htons(tcp_packet->th_sport);
                printf("Src: %u", netflow.srcport);
                netflow.dstport = htons(tcp_packet->th_dport);
                printf("Dst: %u\n", netflow.dstport);
                //printf("src port: %hu\n", htons(tcp_packet->th_sport));
                //printf("dst port: %hu\n", htons(tcp_packet->th_dport));
            }
        }

        //printf("timers %i %i and %u",options.a_timer*1000,options.i_timer*1000, current_time);
        check_timers(options.a_timer*1000,options.i_timer*1000, current_time);

        auto it = netflowMap.find(netflow);
        if(it !=netflowMap.end()){
            it->second.Last = current_time;
            it->second.dPkts += 1;
            it->second.dOctets += netflow_data.dOctets;
        }else{
            printf("CACHE?");
            check_cache(options.count);
            netflow_data.srcaddr = netflow.srcaddr;
            netflow_data.dstaddr = netflow.dstaddr;
            netflow_data.dstport = netflow.dstport;
            netflow_data.srcport = netflow.srcport;
            netflow_data.prot = netflow.prot;
            netflow_data.First = current_time;
            netflow_data.Last = current_time;
            netflow_data.dPkts = 1;

            netflowMap[netflow] = netflow_data; //for the first
        }
    }
    export_all();
    pcap_close(session);
    //TODO:convert hostname to host
    //TODO: cummulative or of tcp flags
    //TODO:hostname validity check
    //TODO:numbers validity check, possible?
    //TODO:stdin empty -program doesnt end, problem??
    //TODO:file validity check
    //TODO: check active flows to export
    //TODO: check inactive flows to export
    //TODO: udp client for export

}

void export_all(){
    cout<<"SRC_ADDR\tDST_ADDR\tNEXTHOP\tIN\tOUT\tPKTS\tOCTETS\tFIRST\tLAST\tSRC_P\tDST_P\tPAD\tTCP\tPROT\tTOS\tSRC_AS\tDST_AS\tSRC_M\tDST_M\tPAD\n";
    for(auto it = netflowMap.cbegin(); it != netflowMap.cend(); )
    {
        cout <<it->second.srcaddr <<"\t"<<it->second.dstaddr <<"\t"<<it->second.nexthop <<"\t"<<it->second.input <<"\t"
             <<it->second.output <<"\t"<<it->second.dPkts<<"\t"<<it->second.dOctets<<"\t"<<it->second.First<<"\t"
             <<it->second.Last<<"\t"<<it->second.srcport<<" "<<it->second.dstport<<"\t"<<unsigned(it->second.pad1)<<"\t"
             <<unsigned(it->second.tcp_flags)<<"\t"<<unsigned(it->second.prot)<<"\t"<<unsigned(it->second.IP)<<"\t"
             <<it->second.src_as<<"\t"<<it->second.dst_as<<"\t"<<unsigned(it->second.src_mask)<<"\t"<<unsigned(it->second.dst_mask)<<"\t"
             <<it->second.pad2<<"\n";
        netflowMap.erase(it++);
    }
}

void check_timers(int atimer,int iatimer, uint32_t current){
        //print_netflow();
        for (auto it = netflowMap.cbegin(); it != netflowMap.cend(); ) {
            if((it->second.Last - it->second.First) >= atimer){
                printf("ACTIVE");
                export_flow(it->first);
                ////delete
                netflowMap.erase(it++);
            }else if((current - it->second.Last) >= iatimer){
                printf("INACTIVE");
                export_flow(it->first);
                ////delete
                netflowMap.erase(it++);
            }else{
                ++it;
            }

        }
}

void export_flow(Netflow_base netflow){

    ////find
    auto it = netflowMap.find(netflow);
    ////print
    cout <<it->second.srcaddr <<"\t"<<it->second.dstaddr <<"\t"<<it->second.nexthop <<"\t"<<it->second.input <<"\t"
    <<it->second.output <<"\t"<<it->second.dPkts<<"\t"<<it->second.dOctets<<"\t"<<it->second.First<<"\t"
    <<it->second.Last<<"\t"<<it->second.srcport<<" "<<it->second.dstport<<"\t"<<unsigned(it->second.pad1)<<"\t"
    <<unsigned(it->second.tcp_flags)<<"\t"<<unsigned(it->second.prot)<<"\t"<<unsigned(it->second.IP)<<"\t"
    <<it->second.src_as<<"\t"<<it->second.dst_as<<"\t"<<unsigned(it->second.src_mask)<<"\t"<<unsigned(it->second.dst_mask)<<"\t"
    <<it->second.pad2<<"\n";

}

void check_cache(uint32_t count){
    Netflow_base latest_key;
    auto it_last = netflowMap.cbegin();
    if(netflowMap.size() == count){
        //printf("CACHE_____FULL");
        for (auto it = netflowMap.cbegin(); it != netflowMap.cend(); it++) {
            if (it->second.First <= it_last->second.First) {
                latest_key = it->first;
                it_last = it;
            }
        }
        export_flow(latest_key);
        ////delete
        netflowMap.erase(it_last);
    }
    return;
}