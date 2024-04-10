#include "nmap.h"

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

static void    craft_icmp_payload(t_data *dt)
{
    int i;

    i = 0;
    ft_bzero(&dt->packet, sizeof(dt->packet));
    while (i < ICMP_P_LEN)
    {
		dt->packet.payload[i] = 'A' + g_sequence;
        i++;
    }
    dt->packet.payload[ICMP_P_LEN - 1] = '\0';
    dt->sequence++;
}

static void    craft_packet(t_data *dt)
{
    craft_icmp_payload(dt);
    dt->packet.h.type = ICMP_ECHO;
    dt->packet.h.un.echo.id = getpid();
    dt->packet.h.un.echo.sequence = dt->sequence;
    dt->packet.h.checksum = checksum(&dt->packet, sizeof(dt->packet));
}

static void    send_packet(t_data *dt)
{
    int r = 0;

    print_info("Main socket is readable");
    if ((r = sendto(dt->socket, &dt->packet, sizeof(dt->packet), 0, (struct sockaddr*)&dt->target_address, sizeof(dt->target_address))) < 0)
    {
        warning("Packet sending failure.");
        return;
    }
    print_info_int("Packet sent (bytes):", sizeof(dt->packet));
    debug_icmp_packet(dt->packet);
    g_end_server = TRUE;
}

void            craft_and_send_packet(t_data *dt)
{
    craft_packet(dt);
    send_packet(dt);
}
