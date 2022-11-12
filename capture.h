#ifndef C_PACKET_SNIFFER_MAIN_H
#define C_PACKET_SNIFFER_MAIN_H

#define ETH_ADDRESS_LENGTH 6
#define ETH_HEADER_LENGTH 14

int packet_number = 1;


struct ethernet_frame {
    unsigned char source_mac_addr[ETH_ADDRESS_LENGTH];
    unsigned char dest_mac_addr[ETH_ADDRESS_LENGTH];
    unsigned short protocol;
};


struct ipv4_header {
    unsigned char ihl : 4;
    unsigned char version : 4;
    unsigned char type_of_service;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_and_fragment_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned int src_ip_addr;
    unsigned int dst_ip_addr;
};


struct ipv6_header {
#if defined(WORDS_BIGENDIAN)
    u_int8_t version:4, traffic_class_high:4;
	u_int8_t traffic_class_low:4, flow_label_high:4;
#else
    unsigned int traffic_class_high :4, version :4;
    unsigned int flow_label_high :4, traffic_class_low :4;
#endif
    unsigned int flow_label_low : 16;
    unsigned int payload_length : 16;
    unsigned char  next_header : 8;
    unsigned char hop_limit : 8;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
};

struct tcp_header {
    unsigned short src_port;
    unsigned short dest_port;
    u_int32_t sequence;
    u_int32_t acknowledgment;
    unsigned char reserved :4;
    unsigned char data_offset :4;
    unsigned char flags;
    unsigned short window_size;
    unsigned short checksum;
    unsigned short urgent_pointer;
};

struct udp_header {
    unsigned int src_port : 16;
    unsigned int dst_port : 16;
    unsigned int length : 16;
    unsigned int checksum : 16;
};

struct icmp_packet {
    unsigned int type : 8;
    unsigned int code : 8;
    unsigned int checksum : 16;
    unsigned char rest_of_header;
};

struct ipv6_ext_headers {
    unsigned int next_header : 8;
    unsigned int header_ext_length : 8;
    u_char options_and_padding;

};


/**
 * Recursively checks the extension headers
 */
int do_extension_headers (int, const u_char *);


/**
 * Prints out the data in raw and ascii format.
 * The raw and ascii correspond with each other, being
 * raw on the lhs, and ascii on the right
 *
 */
void dump (const unsigned char *, unsigned int);

/**
 * Converts a string to a MAC or IPv6 Address
 * in the format of xx:xx... or xxxx::xxxx
 */
void mac_toupper (char *);

/**
 * Unpacks the ethernet frame, prints out the source and destination
 * MAC addresses and returns the protocol
 *
 * @param packet - the parsed data from tcpdump/pcap_file
 * @return - the ethernet protocol - IPv4, IPv6, etc...
 */
int unpack_ethernet_header_frame (const u_char *);


/**
 * Unpacks the IPv4 Packet, prints out the ipv4 header info
 *
 * @param packet - the parsed data from tcpdump + ETHERNET_HEADER_LENGTH
 * @param return - the IPv4 protocol - TCP/UDP/ICMP etc...
 */
int unpack_ipv4_packet (const u_char *);


/**
 * Unpack the IPv6 Packet, prints out the ipv6 header info
 *
 */
int unpack_ipv6_packet (const u_char *);

/**
 * Prints the IPv4 address in the form of 127.0.0.1
 *
 * @param address - the bytes to be converted
 */
void get_ipv4_address (char *, __uint32_t);


/**
 * Print the IPv6 address in the form of xxxx::xxxx
 */
void get_ipv6_address (char *, struct in6_addr);

/**
 * Unpack the tcp segment and print valid information to std.err
 */
void tcp_segment (const u_char *);

/**
 * Unpacks the udp segment and print valid information to std.err
 */
void udp_segment (const u_char *);

/**
 * Unpacks the icmp packet and print valid informaiton to std.err
 */
void icmp_packet (const u_char *);

/**
 * Figures out whether it will be displaying IPv4 or IPv6 protocol.
 * This is done as tcp/udp will use the same functions regardless of
 * ip protocol. The only difference will be ICMPv6
 */
void do_protocol (int, const u_char *, int, unsigned int);


/**
 * The main function for parsing a packet
 */
void got_packet (u_char *, const struct pcap_pkthdr *, const u_char *);

/**
 * Start of program
 */
int main(int, char **);

struct ip_address_data
{
    int eth;
    char src_ip[100];
    char dest_ip[100];
};

struct ip_address_data addresses_data[10000];
int i=0;
void mac_toupper (char *mac)
{
    int i=0;
    while (mac[i])
    {
        putchar (toupper(mac[i]));
        i++;
    }
    printf("\n");
}


int unpack_ethernet_header_frame (const u_char *packet) {

    struct ethernet_frame *eth_frame = (struct ethernet_frame *) packet;

    printf("Source Mac: ");
    mac_toupper(ether_ntoa((struct ether_addr *) eth_frame->source_mac_addr));


    printf("Destination Mac: ");
    mac_toupper(ether_ntoa((struct ether_addr *) eth_frame->dest_mac_addr));

    return eth_frame->protocol;
}

int unpack_ipv4_packet (const u_char *packet) {

    struct ipv4_header *ip_packet = (struct ipv4_header *) packet;

    printf("\tVersion: %d\n", ip_packet->version);
    printf("\tTotal Length: %d\n", ip_packet->total_length);
    printf("\tTime To Live: %d\n", ip_packet->ttl);
    get_ipv4_address("\tSource Address", ip_packet->src_ip_addr);
    get_ipv4_address("\tDestination Address", ip_packet->dst_ip_addr);
    struct in_addr ip;
    ip.s_addr = ip_packet->dst_ip_addr;
    strcpy(addresses_data[i].dest_ip,inet_ntoa(ip));
    ip.s_addr = ip_packet->src_ip_addr;
    strcpy(addresses_data[i].src_ip,inet_ntoa(ip));
    i++;
    return ip_packet->protocol;
}


int unpack_ipv6_packet (const u_char *packet)
{
    struct ipv6_header *ip_packet = (struct ipv6_header *) packet;
    printf("\tVersion: %d\n", ip_packet->version);
    get_ipv6_address("\tSource Address", ip_packet->src_addr);
    get_ipv6_address("\tDestination Address", ip_packet->dst_addr);

    return ip_packet->next_header;
}

void dump (const unsigned char *data_buffer, const unsigned int length) {

    printf("\t\tPayload: (%d bytes)\n\n", length - 32);
    unsigned char byte;
    unsigned int i, j;

    for (i = 0; i < length; i++) {
        byte = data_buffer[i];
        printf("%02x", data_buffer[i]);
        if (((i % 16) == 15) || (i == length - 1)) {
            for (j = 0; j < 15 - (i % 16); j++)
                printf("  ");
            printf("| ");
            for (j = (i - (i % 16)); j <= i; j++) {
                byte = data_buffer[j];
                if ((byte > 31) && (byte < 127))
                    printf("%c", byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

void get_ipv4_address (char *msg, __uint32_t address) {
    struct in_addr ip;
    ip.s_addr = address;

    printf("%s: %s\n", msg, inet_ntoa(ip));
}

void get_ipv6_address (char *string, struct in6_addr ip_address)
{
    char addr[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &ip_address, addr, INET6_ADDRSTRLEN);

    printf("%s: ", string);
    mac_toupper(addr);
}

void tcp_segment (const u_char *packet) {
    struct tcp_header *tcp_segment = (struct tcp_header *) packet;

    printf("\t\tSource Port: %d\n", ntohs(tcp_segment->src_port));
    printf("\t\tDestination Port: %d\n", ntohs(tcp_segment->dest_port));
    printf("\t\tSequence: %d\n", ntohl(tcp_segment->sequence));
    printf("\t\tAcknowledgement: %d\n", ntohl(tcp_segment->acknowledgment));
    printf("\t\tData Offset: %d\n", tcp_segment->data_offset);
}


void udp_segment (const u_char *packet)
{
    struct udp_header *udp_segment = (struct udp_header *) packet;
    printf("\t\tSource Port: %d\n", ntohs(udp_segment->src_port));
    printf("\t\tDestination Port: %d\n", ntohs(udp_segment->dst_port));
    printf("\t\tLength: %d\n", ntohs(udp_segment->length));
}

void icmp_packet (const u_char *packet)
{
    struct icmp_packet *icmp_header = (struct icmp_packet *) packet;

    printf("\t\tType: %d\n", icmp_header->type);
    printf("\t\tCode: %d\n", icmp_header->code);

}

int ipv6_extension_header (const u_char *packet)
{
    struct ipv6_ext_headers *headers = (struct ipv6_ext_headers *)packet;
    printf("\t\tNext Header: %d\n", headers->next_header);
    printf("\t\tOptions: %hhu\n", headers->options_and_padding);

    int next = do_extension_headers(headers->next_header, packet + sizeof(struct ipv6_ext_headers));
    return next;
}

int do_extension_headers (int ip_proto, const u_char *packet)
{
    switch (ip_proto)
    {

        case 0:
            printf("\tHop By Hop:\n");
            ip_proto = ipv6_extension_header (packet);
            break;

        case 60:
            printf("\tDestination (Routing):\n");
            break;

        case 43:
            printf("\tRouting Header:\n");
            break;

        case 44:
            printf("\tFragment Header:\n");
            break;

        case 51:
            printf("\tAuthentication Header:\n");
            break;

        case 50:
            printf("\tEncapsulation Security Payload Header:\n");
            break;

        case 135:
            printf("\tMobility Header:\n");
            break;

        case 59:
            printf("\tNo Next Header:\n");
            break;

        default:
            break;
    }

    return ip_proto;
}


void do_protocol (int ip_proto, const u_char *packet, int ipv, unsigned int header_len)
{

    int ip_header_size = sizeof(struct ipv4_header);        //version 4 by default

    if (ipv == 6)                                           // IPv6 6
        ip_header_size = sizeof(struct ipv6_header);

    packet = packet + ip_header_size;


        // TCP
    if (ip_proto == 6)
    {
        printf("\tTCP Segment:\n");
        tcp_segment(packet);

        // print data
        dump((packet + sizeof(struct tcp_header)), header_len);

    }

        // UDP
    else if (ip_proto == 17)
    {
        printf("\tUDP Segment:\n");
        udp_segment(packet);

        // print data
        dump((packet + sizeof(struct udp_header)), header_len);

    }

        // ICMPv4
    else if (ip_proto == 1)
    {
        printf("\tICMPv4 Packet:\n");
        icmp_packet(packet);

        // print data
        dump((packet + sizeof(struct icmp_packet)), header_len);
    }

    else if (ip_proto == 58)
    {
        printf("\tICMPv6 Packet:\n");

    }

    else
    {
       printf("Unknown\n");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // now we have the packet, we need to break it open
    // we start with the ethernet_frame
    printf("\nEthernet Frame: #%d\n", packet_number++);
    addresses_data[i].eth=packet_number;
    int ip_proto, eth_proto = unpack_ethernet_header_frame(packet);

    switch (eth_proto) {

        case 8:                                     // IPv4
            printf("Protocol: IPv4\n");

            // unpack the IPv4 packet
            ip_proto = unpack_ipv4_packet(packet + ETH_HEADER_LENGTH);

            do_protocol(ip_proto, packet + ETH_HEADER_LENGTH, 4, header->len);

            break;

        case 56710:                                 // IPv6
            printf("Protocol: IPv6\n");

            // unpack the ipv6 packet
            ip_proto = unpack_ipv6_packet(packet + ETH_HEADER_LENGTH);
            ip_proto = do_extension_headers(ip_proto, packet + ETH_HEADER_LENGTH + sizeof(struct ipv6_header));
            do_protocol(ip_proto, packet + ETH_HEADER_LENGTH, 6, header->len);

            break;

        default:
            printf("Protocol: Unknown\n");
            break;
    }

    printf("\n");
}


#endif //C_PACKET_SNIFFER_MAIN_H