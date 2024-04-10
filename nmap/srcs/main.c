#include "nmap.h"

int g_end_server       = FALSE;

void exit_error(char *msg)
{
    printf(C_G_RED"[ERROR]"C_RES" %s\n", msg);
    exit(1);
}

// void    close_poll_fds(int nfds, struct pollfd fds[SOCKETS_NB])
// {
//     for (int i = 0; i < nfds; i++)
//     {
//         if (fds[i].fd >= 0)
//             close(fds[i].fd);
//     }
// }

// void exit_error_close_fds(char *msg, int socket, int nfds, struct pollfd fds[SOCKETS_NB])
// {
//     printf(C_G_RED"[ERROR]"C_RES" %s\n", msg);
//     close(socket);
//     close_poll_fds(nfds, fds);
//     free_all_malloc();
//     exit(1);
// }

void exit_error_close_socket(char *msg, int socket)
{
    printf(C_G_RED"[ERROR]"C_RES" %s\n", msg);
    close(socket);
    free_all_malloc();
    exit(1);
}

void warning_error(char *msg)
{
    printf(C_G_MAGENTA"[WARNING]"C_RES" %s\n", msg);
}

void print_info(char *msg)
{
    printf(C_G_BLUE"[INFO]"C_RES" %s\n", msg);
}

void print_info_int(char *msg, int n)
{
    printf(C_G_BLUE"[INFO]"C_RES" %s %d\n", msg, n);
}

void init_data(t_data *dt)
{
    dt->input_dest          = ft_strdup("1.1.1.1");
    dt->resolved_address    = NULL;
    dt->resolved_hostname   = "";
    dt->socket              = 0;
    dt->dst_port            = 80;
    dt->src_port            = 45555;
    dt->threads_nb          = 2;
    dt->sequence            = 0;
    ft_memset(&(dt->local_address), 0, sizeof(struct sockaddr_in));
    ft_memset(&(dt->target_address), 0, sizeof(struct sockaddr_in));
    dt->target_address.sin_family = AF_INET;
    dt->target_address.sin_port = 0;
    dt->target_address.sin_addr.s_addr = INADDR_ANY;
}

static void    initialise_data(t_data *dt)
{
    init_data(dt);
    resolve_address(dt);
    resolve_hostname(dt);
}

unsigned short checksum(void *packet, int len)
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

void craft_icmp_payload(t_data *dt)
{
    int i;

    i = 0;
    ft_bzero(&dt->packet, sizeof(dt->packet));
    while (i < ICMP_PAYLOAD_LEN)
    {
		dt->packet.payload[i] = 'A';
        i++;
    }
    dt->packet.payload[ICMP_PAYLOAD_LEN - 1] = '\0';
    dt->sequence++;
}

void    craft_packet(t_data *dt)
{
    craft_icmp_payload(dt);
    dt->packet.h.type = ICMP_ECHO;
    dt->packet.h.un.echo.id = getpid();
    dt->packet.h.un.echo.sequence = dt->sequence;
    dt->packet.h.checksum = checksum(&dt->packet, sizeof(dt->packet));
}

void debug_icmp_packet(t_packet packet)
{
    printf("    sizeof(packet): %lu\n", sizeof(packet));
    printf("    packet.payload: %s\n", packet.payload);
    printf("    sizeof(packet.payload): %lu\n", sizeof(packet.payload));
    printf("    packet.h.type: %d\n", packet.h.type);
    printf("    packet.h.code: %d\n", packet.h.code);
    printf("    packet.h.checksum: %d\n", packet.h.checksum);
    printf("    packet.h.un.echo.id: %d\n", packet.h.un.echo.id);
    printf("    packet.h.un.echo.sequence: %d\n", packet.h.un.echo.sequence);
}

void    send_packet(t_data *dt)
{
    int r = 0;

    print_info("Main socket is readable");
    if ((r = sendto(dt->socket, &dt->packet, sizeof(dt->packet), 0, (struct sockaddr*)&dt->target_address, sizeof(dt->target_address))) < 0)
    {
        warning_error("Packet sending failure.");
        return;
    }
    print_info_int("Packet sent (bytes):", sizeof(dt->packet));
    debug_icmp_packet(dt->packet);
    g_end_server = TRUE;
}

void    craft_and_send_packet(t_data *dt)
{
    craft_packet(dt);
    send_packet(dt);
}

int main(int ac, char **av)
{
    t_data          dt;
    int             r = 0;

    (void)ac;
    (void)av;
    initialise_data(&dt);
    open_main_socket(&dt);
    debug_sockaddr_in(&dt.target_address);

    struct pollfd fds[SOCKETS_NB];
    ft_memset(fds, 0 , sizeof(fds));
    fds[0].fd               = dt.socket;
    fds[0].events           = POLLOUT;
    
    while (g_end_server == FALSE)
    {
        printf("Waiting on poll()...\n");
        r = poll(fds, NFDS, POLL_TIMEOUT);
        if (r < 0)
            exit_error("Poll failure.");
        if (r == 0)
            exit_error("Poll timed out.");
        for (int i = 0; i < NFDS; i++)
        {
            if (fds[i].revents == 0)
            {
                printf(C_B_RED"[SHOULD NOT APPEAR] No revent / unavailable yet"C_RES"\n");
                continue;
            }
            if (fds[i].revents != POLLOUT)
                exit_error_close_socket("Poll unexpected result", dt.socket);
            if (fds[i].fd == dt.socket)
                craft_and_send_packet(&dt);
            else
                warning_error("Unknown fd is readable.");
        }
    }
    close(dt.socket);
    free_all_malloc();
    return (0);
}