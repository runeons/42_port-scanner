#ifndef NMAP_H
# define NMAP_H

# include <unistd.h>
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
// # include <signal.h>
// # include <sys/time.h>
// # include <sys/socket.h>
# include <arpa/inet.h>         // inet_ntoa
# include <netdb.h>             // addrinfo
# include <sys/poll.h>
# include <errno.h>
// # include <netinet/ip_icmp.h>   // struct icmphdr
// # include <netinet/udp.h>       // struct udphdr
# include <utils_colors.h>
# include <libft.h>

# define MAX_HOSTNAME_LEN       128
# define SOCKETS_NB             200
# define FALSE                  0
# define TRUE                   1

typedef struct  s_data
{
    char                *input_dest;
    char                *resolved_address;
    char                *resolved_hostname;
    int                 socket;
    struct sockaddr_in  local_address;
    struct sockaddr_in  target_address;
    int                 dst_port;
    int                 src_port;
    int                 threads_nb;
}					t_data;

//  socket.c
void            resolve_hostname(t_data *dt);
void            resolve_address(t_data *dt);
void            bind_socket_to_src_port(t_data *dt, int src_port);
void            open_main_socket(t_data *dt);
void            debug_addrinfo(struct addrinfo *ai);
void            debug_sockaddr_in(struct sockaddr_in *addr);

//  main.c
void            exit_error(char *msg);
void            warning_error(char *msg);
void            print_info(char *msg);
void            print_info_int(char *msg, int n);

#endif
