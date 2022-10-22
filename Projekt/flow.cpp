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
int protocol;

using namespace std;

map<Netflow_base, Netflow> netflowMap;



int main(int argc, char **argv) {
    char err_buf[PCAP_ERRBUF_SIZE]; //control buffer for pcap functions
    int input;

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

    struct pcap_pkthdr packet_header; //contains packet timestamp and caplen -length of frame in bytes
    const u_char *packet;

    //packet time values
    int i = 0;
    uint32_t boot_time;
    uint32_t current_time;

    for(packet = pcap_next(session, &packet_header);packet != NULL; packet = pcap_next(session, &packet_header),i++){

        ////Packet time values
        if(i == 0){
            boot_time =(packet_header.ts.tv_sec * 1000)+(packet_header.ts.tv_usec / 1000);
            printf("saved time %u", boot_time);
        }
        current_time = (packet_header.ts.tv_sec * 1000)+(packet_header.ts.tv_usec / 1000) - boot_time;
        printf("Current %u  \n", current_time);

        ////resolve IP or ICMP port
        ether_packet = (struct ether_header *) packet;

        ////resolve IP dest, source, header size and tos
        if(ntohs(ether_packet->ether_type) == ARP){
            arp_packet = (struct ether_arp *) packet;
            printf("src IP: %d.%d.%d.%d\n", arp_packet->arp_spa[0], arp_packet->arp_spa[1], arp_packet->arp_spa[2],
                   arp_packet->arp_spa[3]);
            printf("dst IP: %d.%d.%d.%d\n", arp_packet->arp_tpa[0], arp_packet->arp_tpa[1], arp_packet->arp_tpa[2],
                   arp_packet->arp_tpa[3]);

        }else if(ntohs(ether_packet->ether_type) == IPV4){
            ipv4_packet = (struct ip *) packet;
            printf("src IP: %s\n", inet_ntoa(ipv4_packet->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ipv4_packet->ip_dst));
            protocol = ipv4_packet->ip_p;
            packet = packet + 4 * ipv4_packet->ip_hl;
        }else if(ntohs(ether_packet->ether_type) == IPV6){
            ipv6_packet = (struct ip6_hdr *) packet;
            printf("src IP: %s\n", inet_ntop(AF_INET6, &(ipv6_packet->ip6_src), src_ip6, INET6_ADDRSTRLEN));
            printf("dst IP: %s\n", inet_ntop(AF_INET6, &(ipv6_packet->ip6_dst), dst_ip6, INET6_ADDRSTRLEN));
        }

        ////TCP, UDP, ICMP support
        if (protocol != ICMP) {
            if (protocol == UDP) {
                struct udphdr *udp_packet;
                udp_packet = (struct udphdr *) packet;
                printf("src port: %hu\n", htons(udp_packet->uh_sport));
                printf("dst port: %hu\n", htons(udp_packet->uh_dport));
            } else if (protocol == TCP) {
                struct tcphdr *tcp_packet;
                tcp_packet = (struct tcphdr *) packet;
                printf("src port: %hu\n", htons(tcp_packet->th_sport));
                printf("dst port: %hu\n", htons(tcp_packet->th_dport));
            }
        }

    }
    pcap_close(session);
    //TODO:convert hostname to host
    //TODO: stdin empty -program doesnt end
    //TODO:help
    //TODO:hostname validity check
    //TODO:file validity check
    //TODO:numbers validity check, possible?

}