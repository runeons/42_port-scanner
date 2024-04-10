#include "nmap.h"

void exit_error(char *msg)
{
    printf(C_G_RED"[ERROR]"C_RES" %s\n", msg);
    exit(1);
}

void    close_poll_fds(int nfds, struct pollfd fds[SOCKETS_NB])
{
    for (int i = 0; i < nfds; i++)
    {
        if (fds[i].fd >= 0)
            close(fds[i].fd);
    }
}

void exit_error_close_fds(char *msg, int socket, int nfds, struct pollfd fds[SOCKETS_NB])
{
    printf(C_G_RED"[ERROR]"C_RES" %s\n", msg);
    close(socket);
    close_poll_fds(nfds, fds);
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


void    close_connection(char *msg, int *close_conn)
{
    warning_error(msg);
    *close_conn = TRUE;
}

unsigned short checksum(void *packet, int len)
{
    unsigned short  *tmp;
	unsigned int    checksum;

    tmp = packet;
    // printf("tmp: %d, len: %d\n", *tmp, len);
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

int main(int ac, char **av)
{
    t_data          dt;

    (void)ac;
    (void)av;
    initialise_data(&dt);
    open_main_socket(&dt);
    debug_sockaddr_in(&dt.target_address);
    craft_packet(&dt);

    struct pollfd fds[SOCKETS_NB];
    ft_memset(fds, 0 , sizeof(fds));
    fds[0].fd               = dt.socket;
    fds[0].events           = POLLOUT;
    int     timeout         = (5 * 60 * 1000);
    // char    buffer[80];
    int     r               = 0;
    int     len             = 0;
    int     nfds            = 1;
    int     rc              = 1;
    int     current_size    = 1;
    int     end_server      = FALSE;
    int     close_conn      = FALSE;
    int     compress_array  = FALSE;

    while (end_server == FALSE)
    {
        printf("Waiting on poll()...\n");
        rc = poll(fds, nfds, timeout);
        if (rc < 0)
            exit_error("Poll failure.");
        if (rc == 0)
            exit_error("Poll timed out.");
        current_size = nfds; // available fds
        printf(C_G_RED"[QUICK DEBUG] nfds: %d"C_RES"\n", nfds);
        for (int i = 0; i < current_size; i++)
        {
            if (fds[i].revents == 0)        // unavailable fds
                continue;        
            if (fds[i].revents != POLLOUT)
                exit_error_close_fds("Poll unexpected result", dt.socket, nfds, fds);
            if (fds[i].fd == dt.socket)
            {
                print_info("Main socket is readable");
                // ... could accept all incoming connections but forbidden function / unnecessary
                if ((r = sendto(dt.socket, &dt.packet, sizeof(dt.packet), 0, (struct sockaddr*)&dt.target_address, sizeof(dt.target_address))) < 0)
                {
                    close_connection("Packet sending failure.", &close_conn);
                    break;

                }
                print_info_int("Packet sent (bytes):", len);
            }
            else
            {
                print_info("New fd is readable");
                // Receive all incoming data
                close_conn = FALSE;
                while (TRUE) // recv until EWOULDBLOCK
                {
                    // rc = recv(fds[i].fd, buffer, sizeof(buffer), 0);
                    // if (rc < 0)
                    // {
                    //     if (errno != EWOULDBLOCK)
                    //         close_connection("Recv failure.", &close_conn);
                    //     break;
                    // }
                    // if (rc == 0)
                    // {
                    //     close_connection("Connection closed by client.", &close_conn);
                    //     break;
                    // }
                    // len = rc;
                    // print_info_int("Data received (bytes):", len);

                    // rc = send(fds[i].fd, buffer, len, 0); // echo data back to the client
                    // if (rc < 0)
                    // {
                    //     close_connection("Send failure.", &close_conn);
                    // }
                }
                if (close_conn)
                {
                    close(fds[i].fd);
                    fds[i].fd = -1;
                    compress_array = TRUE;
                }
            }
        }
        if (compress_array)
        {
            compress_array = FALSE;
            for (int i = 0; i < nfds; i++)
            {
                if (fds[i].fd == -1)
                {
                    for (int j = i; j < nfds-1; j++)
                        fds[j].fd = fds[j+1].fd;
                    i--;
                    nfds--;
                }
            }
        }

    }
    close(dt.socket);
    close_poll_fds(nfds, fds);
    return (0);
}