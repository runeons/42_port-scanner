#ifndef FT_NMAP_H
# define FT_NMAP_H

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
# include <utils_options.h>
# include <libft.h>
# include <pcap.h>
# include <pthread.h>

// GENERAL
# define TRUE                   1
# define FALSE                  0
# define MAX_HOSTNAME_LEN       128
# define SOCKETS_NB             1               // e.g. 200
# define MAX_SCANS              6
# define MAX_PORTS              1024
// DEFAULTS OPTIONS VALUES
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
# define ICMP_ECHO_REPLY        0       // INIT TEST ONLY
// TASKS
# define T_SEND                 1
// ALL SCANS
# define SYN                    0
# define ACK                    1
# define UDP                    2
# define FIN                    3
# define NUL                    4
# define XMAS                   5
# define ICMP                   6       // INIT TEST ONLY
// SCANS
# define OFF                    0
# define ON                     1
// RESPONSES & CONCLUSION
# define IN_PROGRESS            0
// RESPONSES
# define TCP_SYN_ACK            1             
# define TCP_RST                2                 
# define UDP_ANY                3
# define ICMP_UNREACH_C_3       4       // type 3 | code 3
# define ICMP_UNREACH_C_NOT_3   5       // type 3 | code 1, 2, 9, 10, 13
# define NO_RESPONSE            6
# define OTHER                  7
# define ICMP_ECHO              8       // INIT TEST ONLY
// CONCLUSION
# define OPEN                   1
# define CLOSED                 2
# define FILTERED               3
# define OPEN_FILTERED          4
# define UNFILTERED             5

extern int g_end_server;
extern int g_sequence;
extern int g_max_send;
extern int g_task_id;
extern int g_retrieve;
extern int g_sent;
extern int g_queued;
extern int g_verbose;

typedef struct  s_packet
{
	struct icmphdr  h;
	char            payload[ICMP_P_LEN];
}               t_packet;

typedef struct  s_task
{
    int                 id;
    int                 task_type; // SEND, RECV
    int                 scan_type; // ICMP, TCP, UDP
    struct sockaddr_in  target_address;
    int                 dst_port;
}               t_task;

typedef struct s_scan
{
    int     name;
    int     required;
    int     response;
    int     count_sent;
    int     max_send;
    int     conclusion;
}              t_scan;

typedef struct  s_port
{
    struct sockaddr_in  target_address;
    int                 port_id;
    t_scan              scans[6];
    int                 conclusion;
}               t_port;

typedef struct  s_host
{
    struct sockaddr_in  target_address;
    t_lst               *ports;
}               t_host;

typedef struct  s_data
{
    char                *input_dest;
    t_lst               *act_options;
    char                *resolved_address;
    char                *resolved_hostname;
    int                 socket;
    struct sockaddr_in  local_address;
    struct sockaddr_in  target_address;
    int                 dst_port;
    int                 src_port;
    struct pollfd       fds[SOCKETS_NB];
    t_lst               *queue;
    // OPTIONS

    int threads;
    int verbose;

}				t_data;

//  options.c
void            init_options_params(t_data *dt);
//  socket.c
void            resolve_hostname(t_data *dt);
void            resolve_address(t_data *dt);
void            bind_socket_to_src_port(t_data *dt, int src_port);
void            open_main_socket(t_data *dt);
void            debug_addrinfo(struct addrinfo *ai);
void            debug_sockaddr_in(struct sockaddr_in *addr);

// packet.c
void            craft_and_send_icmp(int socket, t_packet *packet, t_task *task);

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

// sniffer.c
void            prepare_sniffer(pcap_t **handle);
void            retrieve_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void            sniff_packets(pcap_t *handle);

// init_data.c
void            init_data(t_data *dt, t_parsed_cmd *parsed_cmd);
void            add_destination(t_data *dt, char *curr_arg);
void            initialise_data(t_data *dt, t_parsed_cmd *parsed_cmd);

// tasks.c
void            enqueue_task(t_data *dt, t_task *task);
t_task          *dequeue_task(t_data *dt);
t_task          *create_task(int socket, struct sockaddr_in target_address, int dst_port);
void            init_queue(t_data *dt);


#endif
