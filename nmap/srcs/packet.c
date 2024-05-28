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

void    craft_ip_header(struct ip *ip_h, t_task *task)
{
    ip_h->ip_hl         = IP_HL;
    ip_h->ip_v          = IP_VERSION;
    ip_h->ip_ttl        = 64; // curr_ttl
    ip_h->ip_p          = IPPROTO_UDP;
    ip_h->ip_src.s_addr = INADDR_ANY;
    ip_h->ip_dst        = task->target_address.sin_addr;
}

void    craft_udp_header(struct udphdr *udp_h, t_task *task)
{
    udp_h->uh_sport = htons(12345); // src_port
    udp_h->uh_dport = htons(task->dst_port);
    udp_h->uh_ulen  = htons(UDP_H_LEN + UDP_P_LEN);
}

void construct_udp_packet(t_packet *packet, t_task *task)
{
    printf(TEST);
    packet->type = task->scan_type ;
    packet->size = sizeof(struct ip) + sizeof(struct udphdr) + UDP_P_LEN;
    ft_bzero(&packet->packet(udp), packet->size + UDP_P_LEN);

    craft_ip_header(&packet->packet(udp).iph, task);
    craft_udp_header(&packet->packet(udp).h, task);

    for (int i = 0; i  < UDP_P_LEN; i++)
		packet->packet(udp).payload[i] = 'A';
}

void construct_tcp_packet(t_packet *packet, t_task *task)
{
    printf(TEST);
    packet->type = task->scan_type;
    packet->size = sizeof(struct tcphdr) + 2 * sizeof(uint8_t) + sizeof(uint16_t);

    struct tcphdr *tcph = &packet->packet(tcp).h;
    ft_bzero(&packet->packet(tcp), packet->size);

    // TCP header
    tcph->source    = htons( (getpid() & 0xffff) | 0x8000);
    tcph->dest      = htons(task->dst_port);
    tcph->seq       = htonl(g_sequence++); // all the globals need mutex when used in threads;
    tcph->ack_seq   = 0;
    tcph->doff      = (sizeof(struct tcphdr))/4 + 1; // TCP header size
    switch (packet->type)
    {
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
    tcph->window    = htons(1024);
    tcph->urg_ptr   = 0;

    uint8_t *options = (uint8_t *)tcph + sizeof(struct tcphdr);
    options[0] = 2; // Kind
    options[1] = 4; // Length
    *(uint16_t *)(options + 2) = htons(1460); // Value (MSS)
    tcph->check = checksum(&packet->packet(tcp), packet->size);
    display_tcphdr(tcph);
    display_tcp_packet(*packet);
}

void    send_packet(int socket, t_packet *packet, struct sockaddr_in *target_address, int task_id)
{
    printf(TEST);
    int r = 0;

    // print_info("Main socket is readable");
    if ((r = sendto(socket, &packet->packet(generic), packet->size, 0, (struct sockaddr *)target_address, sizeof(*target_address))) < 0)
    {
        warning_int("Packet sending failure.", task_id);
        return;
    }
    print_info_int("Packet sent (bytes):", sizeof(*packet));
    // display_icmp_packet(*packet);
    g_sent++;
}
