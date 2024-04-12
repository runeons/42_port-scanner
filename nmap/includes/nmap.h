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
# include <netinet/ip_icmp.h>   // struct icmphdr
// # include <netinet/udp.h>       // struct udphdr
# include <utils_colors.h>
# include <libft.h>
# include <pcap.h>
# include <pthread.h>

// GENERAL
# define TRUE                   1
# define FALSE                  0
# define MAX_HOSTNAME_LEN       128
# define SOCKETS_NB             1               // e.g. 200
// THREADS
# define THREADS_NB             4
// POLL
# define NFDS                   1
# define POLL_TIMEOUT           5 * 60 * 1000   // 5 minutes
// PCAP
# define PROMISCUOUS            1
// PACKETS SIZES
# define ETH_H_LEN              14
# define IP_H_LEN               20  // sizeof(struct iphdr)
# define ICMP_H_LEN             8   // sizeof(struct icmphdr)
# define ICMP_P_LEN             56
// PACKETS FLAGS
# define ICMP_ECHO_REPLY        0
// TASKS
# define SEND                   1
# define ICMP                   1


extern int g_end_server;
extern int g_sequence;
extern int g_max_send;
extern int g_task_id;

typedef struct  s_packet
{
	struct icmphdr  h;
	char            payload[ICMP_P_LEN];
}               t_packet;

typedef struct  s_scan_task
{
    int                 id;
    int                 task_type; // SEND, RECV
    int                 scan_type; // ICMP, TCP, UDP
    struct sockaddr_in  target_address;
    int                 dst_port;
}               t_scan_task;


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
    t_packet            packet;
    struct pollfd       fds[SOCKETS_NB];
}				t_data;

//  socket.c
void            resolve_hostname(t_data *dt);
void            resolve_address(t_data *dt);
void            bind_socket_to_src_port(t_data *dt, int src_port);
void            open_main_socket(t_data *dt);
void            debug_addrinfo(struct addrinfo *ai);
void            debug_sockaddr_in(struct sockaddr_in *addr);

// packet.c
void            craft_and_send_icmp(int socket, t_packet *packet, t_scan_task *task);

// utils_debug.c
void            debug_icmp_packet(t_packet packet);
void            debug_interfaces(pcap_if_t *interfaces);
void            debug_net_mask(bpf_u_int32 net_mask, bpf_u_int32 dev_mask);

// utils_print.c
void            print_info(char *msg);
void            print_info_int(char *msg, int n);
void            print_info_task(char *msg, int n);

// utils_error.c
void            exit_error(char *msg);
void            exit_error_str(char *msg, char *error);
void            exit_error_close_socket(char *msg, int socket);
void            warning(char *msg);
void            warning_str(char *msg, char *error);
void            warning_int(char *msg, int nb);


#endif