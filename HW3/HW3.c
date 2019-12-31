#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>

struct ip_header{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct tcp_header{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_hlr;
    u_char th_flag;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

struct udp_header{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
};

int count = 1;
char total_src_ip[1024][20];
char total_dst_ip[1024][20];
int total[1024] = {0};

void ip_statistics(char src_ip[], char dst_ip[]){
    for(int i = 0;; i++){
        if(total[i] == 0){
            strcpy(total_src_ip[i], src_ip);
            strcpy(total_dst_ip[i], dst_ip);
            total[i] = 1;
            break;
        }
        else if(strcmp(src_ip, total_src_ip[i]) == 0 && strcmp(dst_ip, total_dst_ip[i]) == 0){
            total[i]++;
            break;
        }
    }
}

void print_total_ip(){
    printf("Total IP Address\n");

    for(int i = 0;; i++){
        if(total[i] == 0)
            break;
        
        printf("%15s -> %15s Total : %4d\n", total_src_ip[i], total_dst_ip[i], total[i]);
    }
}

void dump_tcp(const bpf_u_int32 length, const u_char *content){
    struct ip_header *ip = (struct ip_header *) (content + ETHER_HDR_LEN);
    int ip_size = ip->ip_vhl & 0x0f;

    struct tcp_header *tcp = (struct tcp_header *) (content + ETHER_HDR_LEN + ip_size * 4);

    printf("Source Port : %u\t", ntohs(tcp->th_sport));
    printf("Destination Port : %u\n", ntohs(tcp->th_dport));
}

void dump_udp(const bpf_u_int32 length, const u_char *content){
    struct ip_header *ip = (struct ip_header *) (content + ETHER_HDR_LEN);
    int ip_size = ip->ip_vhl & 0x0f;

    struct udp_header *udp = (struct udp_header *) (content + ETHER_HDR_LEN + ip_size * 4);

    printf("Source Port : %u\t", ntohs(udp->uh_sport));
    printf("Destination Port : %u\n", ntohs(udp->uh_dport));
}

void dump_ip(const bpf_u_int32 length, const u_char *content){
    struct ip_header *ip = (struct ip_header *) (content + ETHER_HDR_LEN);
    char src_ip[20] = {0};
    char dst_ip[20] = {0};

    sprintf(src_ip, "%s", inet_ntoa(ip->ip_src));
    sprintf(dst_ip, "%s", inet_ntoa(ip->ip_dst));

    printf("Source IP Address : %s\t", src_ip);
    printf("Destination IP Address : %s\n", dst_ip);

    ip_statistics(src_ip, dst_ip);

    switch (ip->ip_p){
        case IPPROTO_TCP:
            printf("Protocol : TCP\n");
            dump_tcp(length, content);
            break;

        case IPPROTO_UDP:
            printf("Protocol : UDP\n");
            dump_udp(length, content);
            break;
        
        case IPPROTO_ICMP:
            printf("Protocol : ICMP\n");
            break;

        default:
            printf("Protocol : %d\n", ip->ip_p);
            break;
    }
}

void dump_ipv6(const bpf_u_int32 length, const u_char *content){
    struct ip6_hdr *ipv6 = (struct ip6_hdr *) content;
    char src_ip[20] = {0};
    char dst_ip[20] = {0};
}

void dump_ethernet(const bpf_u_int32 length, const u_char *content){
    struct ether_header *ethernet = (struct ether_header *) content;
    char src_mac[20] = {0};
    char dst_mac[20] = {0};

    u_int8_t *d1 = (u_int8_t *) ethernet->ether_shost;
    sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", d1[0], d1[1], d1[2], d1[3], d1[4], d1[5]);

    u_int8_t *d2 = (u_int8_t *) ethernet->ether_dhost;
    sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", d2[0], d2[1], d2[2], d2[3], d2[4], d2[5]);

    printf("Source MAC Address : %s\t", src_mac);
    printf("Destination MAC Address : %s\n", dst_mac);

    switch(ntohs(ethernet->ether_type)){
        case ETHERTYPE_ARP:
            printf("Protocol : ARP\n");
            break;

        case ETHERTYPE_IP:
            printf("Protocol : IP\n");
            dump_ip(length, content);
            break;

        case ETHERTYPE_REVARP:
            printf("Protocol : REVARP\n");
            break;

        case ETHERTYPE_IPV6:
            printf("Protocol : IPv6\n");
            dump_ipv6(length, content);
            break;
    
        default:
            printf("Protocol : 0x%04x\n", ethernet->ether_type);
            break;
    }
}

void pcap_manage(u_char *arg, const struct pcap_pkthdr *header, const u_char *content){
    printf("No.%d\n", count++);

    struct tm *ltime;
    char timestr[100];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%Y/%m/%d %H:%M:%S", ltime);
    printf("Time : %s\n", timestr);

    dump_ethernet(header->caplen, content);

    printf("\n");
}

int main(int argc, char *argv[]){
    char *device = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    if(argc > 2 && strcmp(argv[1], "-r") == 0)
        handle = pcap_open_offline(argv[2], error_buffer);
    else{
        device = pcap_lookupdev(error_buffer);
        printf("Sniffing : %s\n", device);

        handle = pcap_open_live(device, 65535, 0, 10, error_buffer);
    }

    pcap_loop(handle, -1, pcap_manage, NULL);

    print_total_ip();

    return 0;
}