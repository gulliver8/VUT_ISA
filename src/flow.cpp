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

#include <iostream>

struct ether_header *ether_packet;
struct ip *ipv4_packet;
struct ip6_hdr *ipv6_packet;
struct ether_arp *arp_packet;

tuple<uint32_t,uint32_t,uint16_t,uint16_t,uint8_t>netflow_base;
map<Netflow_base, Netflow> netflowMap;

void export_all(Options *options);
void check_timers(long int current, Options *options);
void export_flow(Netflow_base netflow,Options *options);
void check_cache(Options *options);

int main(int argc, char **argv) {

    char err_buf[PCAP_ERRBUF_SIZE]; //control buffer for pcap functions
    //int input;
    int protocol;

    ////get program options
    Options options = {60,10,1024,"127.0.0.1", {},2055,0,"-", 0,0,0};
    inet_aton((options.hostname).c_str(),&options.ip);
    get_options(argc, argv, &options);


    //// open pcap session
    pcap_t *session = NULL;
    session = pcap_open_offline(options.source.c_str(), err_buf);
    if (session == NULL) {
        fprintf(stderr, "Couldn't open file %s: %s\n", options.source.c_str(), err_buf);
        exit(INVALID_FILE);
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
    }

    options.sock = client(options);

    struct pcap_pkthdr packet_header; //contains packet timestamp and caplen -length of frame in bytes
    const u_char *packet;

    //packet time values
    int i = 0;
    long int boot_time;
    long int current_time;
    uint8_t t_flags;
    for(packet = pcap_next(session, &packet_header);packet != NULL; packet = pcap_next(session, &packet_header),i++){
        Netflow_base netflow = {};
        Netflow netflow_data = {};
        t_flags = 0;
        ////Packet time values
        options.secs = packet_header.ts.tv_sec;
        options.n_secs = packet_header.ts.tv_usec;
        if(i == 0){
            boot_time =((packet_header.ts.tv_sec * (uint32_t)1000)+(packet_header.ts.tv_usec / (uint32_t)1000)); //sys_up_time
        }

        current_time = (packet_header.ts.tv_sec * (uint32_t)1000)+(packet_header.ts.tv_usec / (uint32_t)1000) - boot_time;
        //printf("Current %lu  \n", current_time);

        ////resolve IP or ICMP port
        ether_packet = (struct ether_header *) packet;

        packet = packet + 14; //cut the ethernet (datalink) header (14 bytes length)

        ////resolve IP dest, source, header size and tos
        if(ntohs(ether_packet->ether_type) == ARP){
            arp_packet = (struct ether_arp *) packet;
            netflow.srcaddr = *arp_packet->arp_spa;
            netflow.dstaddr = *arp_packet->arp_tpa;
            netflow.prot = arp_packet->ea_hdr.ar_pro;
        }else if(ntohs(ether_packet->ether_type) == IPV4){
            ipv4_packet = (struct ip *) packet;
            netflow.srcaddr = ipv4_packet->ip_src.s_addr;
            netflow.dstaddr = ipv4_packet->ip_dst.s_addr;
            protocol = ipv4_packet->ip_p;
            netflow.prot = ipv4_packet->ip_p;
            netflow_data.dOctets = ntohl(ipv4_packet->ip_hl);
            netflow_data.IP = ipv4_packet->ip_tos;
            packet = packet + 4 * ipv4_packet->ip_hl;
        }else{
            continue;   //ipv6 packets not supported -skip packet
        }
        ////TCP, UDP, ICMP support
        if (protocol != ICMP) {
            if (protocol == UDP) {
                struct udphdr *udp_packet;
                udp_packet = (struct udphdr *) packet;
                netflow.srcport = udp_packet->source;
                //printf("Src: %u", netflow.srcport);
                netflow.dstport = udp_packet->dest;
                //printf("Dst: %u\n", netflow.dstport);
                //printf("src port: %hu\n", htons(udp_packet->uh_sport));
                //printf("dst port: %hu\n", htons(udp_packet->uh_dport));
            }else if (protocol == TCP) {
                struct tcphdr *tcp_packet;
                tcp_packet = (struct tcphdr *) packet;
                netflow.srcport = tcp_packet->th_sport;
                //printf("Src: %u", netflow.srcport);
                netflow.dstport = tcp_packet->th_dport;
                //printf("Dst: %u\n", netflow.dstport);
                t_flags = tcp_packet->th_flags;
                //printf("src port: %hu\n", htons(tcp_packet->th_sport));
                //printf("dst port: %hu\n", htons(tcp_packet->th_dport));
            }
        }
        //printf("JOOJ%u", current_time);
        //printf("timers %i %i and %u",options.a_timer*1000,options.i_timer*1000, current_time);
        check_timers(current_time, &options);

        auto it = netflowMap.find(netflow);
        if(it !=netflowMap.end()){
            it->second.Last = htonl(current_time);
            it->second.dPkts += htonl(1);
            it->second.tcp_flags = t_flags | it->second.tcp_flags;
            it->second.dOctets += netflow_data.dOctets;
        }else{
            check_cache(&options);
            netflow_data.srcaddr = netflow.srcaddr;
            netflow_data.dstaddr = netflow.dstaddr;
            netflow_data.dstport = netflow.dstport;
            netflow_data.srcport = netflow.srcport;
            netflow_data.prot = netflow.prot;
            netflow_data.tcp_flags = t_flags;
            netflow_data.First = htonl(current_time);
            netflow_data.Last = htonl(current_time);
            netflow_data.dPkts = htonl(1);

            netflowMap[netflow] = netflow_data; //for the first record in flow, input whole structure
        }
    }
    export_all(&options);
    close(options.sock);
    printf("* Closing the client socket ...\n");
    pcap_close(session);
}

void export_all(Options *options){
    //cout<<"SRC_ADDR\tDST_ADDR\tNEXTHOP\tIN\tOUT\tPKTS\tOCTETS\tFIRST\tLAST\tSRC_P\tDST_P\tPAD\tTCP\tPROT\tTOS\tSRC_AS\tDST_AS\tSRC_M\tDST_M\tPAD\n";
    for(auto it = netflowMap.cbegin(); it != netflowMap.cend(); )
    {
        export_flow(it->first, options);
        netflowMap.erase(it++);
    }
}

void check_timers(long int current, Options *options){
        //print_netflow();
        for (auto it = netflowMap.cbegin(); it != netflowMap.cend(); ) {
            if((ntohl(it->second.Last) - ntohl(it->second.First)) >= options->a_timer*1000){
                export_flow(it->first,options);
                ////delete
                netflowMap.erase(it++);
            }else if((current - ntohl(it->second.Last)) >= options->i_timer*1000){
                //printf("current: %lu last: %u result: %lu timer: %u ",current,ntohl(it->second.Last),(current - ntohl(it->second.Last)),options->i_timer);
                export_flow(it->first,options);
                ////delete
                netflowMap.erase(it++);
            }else{
                ++it;
            }

        }
}

void export_flow(Netflow_base netflow,Options *options){

    char buffer[BUFFER];
    options->flow_count++;

    ////find
    auto it = netflowMap.find(netflow);
    Netflow net = it->second;
    Netflow_hdr header = {htons(5),htons(1),it->second.Last, htonl(options->secs), htonl(options->n_secs),options->flow_count};
    memcpy(buffer,&header, sizeof(struct Netflow_hdr));
    memcpy(buffer+sizeof(struct Netflow_hdr),&net, sizeof(struct Netflow));
    int msg_size = sizeof(buffer);
    int i = send(options->sock,buffer,msg_size,0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
        printf("send() failed");
    else if (i != msg_size)
        printf("send(): buffer written partially");
}

void check_cache(Options *options){
    Netflow_base latest_key;
    auto it_last = netflowMap.cbegin();
    if(netflowMap.size() == options->count){
        for (auto it = netflowMap.cbegin(); it != netflowMap.cend(); it++) {
            if (it->second.First <= it_last->second.First) {
                latest_key = it->first;
                it_last = it;
            }
        }
        export_flow(latest_key,options);
        ////delete
        netflowMap.erase(it_last);
    }
    return;
}