#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

int MAX_PRINT_LEN;

/* Ethernet header */
struct ethheader
{
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};

/* TCP Header */
struct tcpheader
{
    u_short tcp_sport; /* source port */
    u_short tcp_dport; /* destination port */
    u_int tcp_seq;     /* sequence number */
    u_int tcp_ack;     /* acknowledgement number */
    u_char tcp_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short tcp_win; /* window */
    u_short tcp_sum; /* checksum */
    u_short tcp_urp; /* urgent pointer */
};

/* event handler when packet is captured */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    printf("------------------------------------\n");

    // print mac address
    printf("   src mac : ");
    for (int i = 0; i < 5; i++)
    {
        printf("%x:", eth->ether_shost[i]);
    }
    printf("%x\n", eth->ether_shost[5]);
    printf("   dst mac : ");
    for (int i = 0; i < 5; i++)
    {
        printf("%x:", eth->ether_dhost[i]);
    }
    printf("%x\n", eth->ether_dhost[5]);

    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("    src ip : %s\n", inet_ntoa(ip->iph_sourceip));
        printf("    dst ip : %s\n", inet_ntoa(ip->iph_destip));

        /* determine protocol */
        if (ip->iph_protocol == IPPROTO_TCP)
        {
            printf("   Protocol: TCP\n");
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct tcpheader));

            // print tcp port
            printf("  src port : %d\n", tcp->tcp_sport);
            printf(" dest port : %d\n", tcp->tcp_sport);

            // get TCP header, payload length
            int tcp_header_len = (tcp->tcp_offx2 & 0xF0) >> 4;
            int total_header_size = sizeof(struct ethheader) + sizeof(struct ipheader) + tcp_header_len * 4;
            int payload_len = header->caplen - total_header_size;
            const u_char *payload = packet + total_header_size;

            // print tcp msg, but not too long
            int print_len = payload_len > MAX_PRINT_LEN ? MAX_PRINT_LEN : payload_len;
            printf("   [msg start]\n");
            for (int i = 0; i < print_len; i++)
            {
                printf("%c", *(payload + i));
            }
            printf("\n   [msg end]\n");
        }
        else
        {
            // if not tcp protocol, do nothing
            // printf("not a TCP protocol\n");
        }
    }
}

int main()
{
    // find all NIC devices;
    pcap_if_t *alldevs;
    pcap_if_t *dev;

    char error_buf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, error_buf) < 0)
    {
        printf("no device found.. \n");
        return 0;
    }

    int i = 1;
    for (dev = alldevs; dev; dev = dev->next)
    {
        printf("[%d] device found : %s \n", i++, dev->name);
    }

    int dev_num;

    // select device
    printf("\n1. Choose your NIC device(input number) : ");
    scanf("%d", &dev_num);
    dev = alldevs;
    for (int i = 0; i < dev_num - 1; i++)
    {
        dev = dev->next;
    }
    printf("Selected device : %s\n", dev->name);

    printf("\n2. Input Max Size of data payload(bytes) : ");
    scanf("%d", &MAX_PRINT_LEN);

    printf("--------capture start--------\n");

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // print only tcp packets
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}
