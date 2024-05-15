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
