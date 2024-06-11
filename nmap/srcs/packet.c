#include "../includes/ft_nmap.h"

static unsigned short checksum(void *packet, int len)
{
    unsigned short  *tmp;
	unsigned int    checksum;

    tmp = packet;
    checksum = 0;
    while (len > 1)
    {
        checksum += *tmp++;
        len -= sizeof(unsigned short);
    }
	if (len == 1)
		checksum += *(unsigned char*)tmp;
	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);
	checksum = (unsigned short)(~checksum);
	return checksum;
}

static void    craft_icmp_payload(t_packet *packet)
{
    int i;

    i = 0;
    ft_bzero(&packet->packet(icmp), packet->size);
   
    while (i < ICMP_P_LEN)
    {
		packet->packet(icmp).payload[i] = 'A';
        i++;
    }
    packet->packet(icmp).payload[ICMP_P_LEN - 1] = '\0';
    g_sequence++;
}

void    craft_icmp_packet(t_packet *packet, t_task *task)
{
    packet->type = PACKET_TYPE_ICMP;
    packet->size = sizeof(struct icmp_packet);
    craft_icmp_payload(packet);
    packet->packet(icmp).h.type = ICMP_ECHO;
    packet->packet(icmp).h.un.echo.id = task->scan_tracker_id;
    packet->packet(icmp).h.un.echo.sequence = g_sequence;
    packet->packet(icmp).h.checksum = checksum(&packet->packet(icmp), packet->size);
}

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t size;
    };

unsigned char dns_query_payload[] = {
    0x1a, 0x2b, // Transaction ID
    0x01, 0x00, // Flags (Standard query, recursion desired)
    0x00, 0x01, // Questions (1)
    0x00, 0x00, // Answer RRs (0)
    0x00, 0x00, // Authority RRs (0)
    0x00, 0x00, // Additional RRs (0)
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // Query Name: "example"
    0x03, 0x63, 0x6f, 0x6d, // Query Name: "com"
    0x00, // End of Query Name
    0x00, 0x01, // Query Type (A)
    0x00, 0x01  // Query Class (IN)
};


void construct_udp_packet(t_packet *packet, t_task *task) {
    packet->type = task->scan_type;
    packet->size = sizeof(struct udphdr) + UDP_P_LEN;
    // Clear packet data
    ft_bzero(&packet->packet(udp), packet->size);

    for  (int i = 0; i  < UDP_P_LEN; i++)
    {
		packet->packet(udp).payload[i] = 'A';
        //i++;
    }
    ft_memcpy(packet->packet(udp).payload, dns_query_payload, sizeof(dns_query_payload));

    packet->packet(udp).h.source = htons(task->src_port);
    packet->packet(udp).h.dest = htons(task->dst_port);
    packet->packet(udp).h.len = htons(packet->size);

    struct pseudo_header ps;
    ps.source_address = task->src_ip;
    ps.dest_address = task->target_address.sin_addr.s_addr;
    ps.placeholder = 0;
    ps.protocol = IPPROTO_UDP;
    ps.size = htons(packet->size);

    // Calculate the checksum
    int pseudo_packet_size = sizeof(struct pseudo_header) + packet->size;
    uint8_t pseudo_packet[sizeof(struct pseudo_header) + packet->size]; 

    memcpy(pseudo_packet, &ps, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), &packet->packet(udp), packet->size);

    packet->packet(udp).h.check = checksum(pseudo_packet, pseudo_packet_size);;
}

void construct_tcp_packet(t_packet *packet, t_task *task) {
    packet->type = task->scan_type;
    packet->size = sizeof(struct tcphdr) + sizeof(packet->packet(tcp).payload);

    struct tcphdr *tcph = &packet->packet(tcp).h;

    ft_bzero(&packet->packet(tcp), packet->size);

    // TCP header
    tcph->source = htons(task->src_port);
    tcph->dest = htons(task->dst_port);
    //tcph->seq = task->scan_tracker_id; // all the globals need mutex when used in threads;
    //tcph->ack_seq = htonl(task->scan_tracker_id);
    tcph->doff = (sizeof(struct tcphdr)) / 4 + 1; // TCP header size + 1 for the options
    switch (packet->type) {
        case PACKET_TYPE_ACK:
            tcph->th_flags |= TH_ACK;
            break;
        case PACKET_TYPE_FIN:
            tcph->th_flags |= TH_FIN;
            break;
        case PACKET_TYPE_SYN:
            tcph->th_flags |= TH_SYN;
            break;
        case PACKET_TYPE_XMAS:
            tcph->th_flags |= TH_FIN | TH_PUSH | TH_URG;
            break;
        case PACKET_TYPE_NUL:
            break;
        default:
            break;
    }
    tcph->window = htons(1024);

    uint8_t *options = (uint8_t *)tcph + sizeof(struct tcphdr);
    options[0] = 2; // Kind
    options[1] = 4; // Length
    *(uint16_t *)(options + 2) = htons(1460); // Value (MSS)


    // Pseudo header
    struct pseudo_header ps;
    ps.source_address = task->src_ip;
    ps.dest_address = task->target_address.sin_addr.s_addr;
    ps.placeholder = 0;
    ps.protocol = IPPROTO_TCP;
    ps.size = htons(packet->size);

    // Calculate the checksum
    int pseudo_packet_size = sizeof(struct pseudo_header) + packet->size;
    uint8_t pseudo_packet[sizeof(struct pseudo_header) + packet->size]; 

    //uint8_t *pseudo_packet = malloc(pseudo_packet_size);
    memcpy(pseudo_packet, &ps, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, packet->size);

    tcph->check = checksum(pseudo_packet, pseudo_packet_size);

    //free(pseudo_packet);
}

void    send_packet(int socket, t_packet *packet, struct sockaddr_in *target_address, int task_id)
{
    int r = 0;

    // print_info("Main socket is readable");
    if ((r = sendto(socket, &packet->packet(generic), packet->size, 0, (struct sockaddr *)target_address, sizeof(*target_address))) < 0)
    {
        warning_int("Packet sending failure.", task_id);
        return;
    }
    print_info_int("Packet sent (bytes):", sizeof(*packet));
    g_sent++;
    // debug_icmp_packet(*packet);
}
