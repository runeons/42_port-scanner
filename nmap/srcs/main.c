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

int main(int ac, char **av)
{
    t_data          dt;

    (void)ac;
    (void)av;
    initialise_data(&dt);
    open_main_socket(&dt);
    debug_sockaddr_in(&dt.target_address);

    struct pollfd fds[SOCKETS_NB];
    ft_memset(fds, 0 , sizeof(fds));
    fds[0].fd               = dt.socket;
    fds[0].events           = POLLIN;
    int     timeout         = (5 * 1000); // 5 seconds
    char    buffer[80];
    int     i               = 0;
    int     j               = 0;
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
        for (i = 0; i < current_size; i++)
        {
            if (fds[i].revents == 0)        // unavailable fds
                continue;        
            if (fds[i].revents != POLLIN)
                exit_error_close_fds("Poll unexpected result", dt.socket, nfds, fds);
            if (fds[i].fd == dt.socket)
            {
                print_info("Listening socket is readable");
                // ... could accept all incoming connections but forbidden function / unnecessary
            }
            else
            {
                print_info("New fd is readable");
                // ... Receive all incoming 
                close_conn = FALSE;
                while (TRUE) // recv until EWOULDBLOCK
                {
                    rc = recv(fds[i].fd, buffer, sizeof(buffer), 0);
                    if (rc < 0)
                    {
                        if (errno != EWOULDBLOCK)
                        {
                            warning_error("Recv failure.");
                            close_conn = TRUE;
                        }
                        break;
                    }
                    if (rc == 0)
                    {
                        print_info("Connection closed by client");
                        close_conn = TRUE;
                        break;
                    }
                    len = rc;
                    print_info_int("Data received (bytes):", len);
                    rc = send(fds[i].fd, buffer, len, 0); // echo data back to the client
                    if (rc < 0)
                    {
                        warning_error("Send failure.");
                        close_conn = TRUE;
                        break;
                    }
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
            for (i = 0; i < nfds; i++)
            {
                if (fds[i].fd == -1)
                {
                    for(j = i; j < nfds-1; j++)
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