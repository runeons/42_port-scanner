#include "nmap.h"

int g_end_server       = FALSE;
int g_sequence         = 0;
int g_max_send         = 220;
int g_task_id          = 0;
int g_retrieve         = 0;

const struct iphdr          *ip_h;
const struct icmphdr        *icmp_h;
const char                  *icmp_payload;

pthread_mutex_t     mutex       = PTHREAD_MUTEX_INITIALIZER;
t_scan_task         task_queue[1028];
int                 queue_front = 0;
int                 queue_rear  = 0;

void init_data(t_data *dt)
{
    dt->input_dest          = ft_strdup("1.1.1.1");
    dt->resolved_address    = NULL;
    dt->resolved_hostname   = "";
    dt->socket              = 0;
    dt->dst_port            = 80;
    dt->src_port            = 45555;
    ft_memset(&(dt->local_address),  0, sizeof(struct sockaddr_in));
    ft_memset(&(dt->target_address), 0, sizeof(struct sockaddr_in));
    dt->target_address.sin_family       = AF_INET;
    dt->target_address.sin_port         = 0;
    dt->target_address.sin_addr.s_addr  = INADDR_ANY;
    ft_memset(dt->fds, 0, sizeof(dt->fds));
    dt->fds[0].events       = POLLOUT;
}

static void    initialise_data(t_data *dt)
{
    init_data(dt);
    resolve_address(dt);
    resolve_hostname(dt);
}

void    prepare_sniffer(pcap_t **handle)
{
    pcap_if_t           *interfaces;
    char                device[] = "enp0s3";
    char                filter[] = "src host 1.1.1.1";
    struct bpf_program  compiled_filter;
    char                err_buf[PCAP_ERRBUF_SIZE];          // 256 from pcap.h
    bpf_u_int32         dev_mask;		                    // The netmask of our sniffing device
    bpf_u_int32         net_mask;		                    // The IP of our sniffing device   

    if (pcap_lookupnet(device, &net_mask, &dev_mask, err_buf) == -1) // get network mask needed for the filter
    {
        warning_str("No network mask for device:", device);
        net_mask = 0;
        dev_mask = 0;
    }
    // debug_net_mask(net_mask, dev_mask);
    if (pcap_findalldevs(&interfaces, err_buf) == -1)
        exit_error_str("Finding devices", err_buf);
    // debug_interfaces(interfaces);
    if ((*handle = pcap_open_live(device, BUFSIZ, PROMISCUOUS, 1000, err_buf)) == NULL)  // sniff device until error and store it in err_buf
        exit_error_str("Opening device:", err_buf);
    if (pcap_compile(*handle, &compiled_filter, filter, 0, net_mask) == -1)
        exit_error_str("Parsing filter:", pcap_geterr(*handle));
    if (pcap_setfilter(*handle, &compiled_filter) == -1)
        exit_error_str("Compiling filter:", pcap_geterr(*handle));
}

void    enqueue_task(t_scan_task task)
{
    pthread_mutex_lock(&mutex);
    task_queue[queue_rear++] = task;
    pthread_mutex_unlock(&mutex);
}

t_scan_task dequeue_task()
{
    pthread_mutex_lock(&mutex);
    t_scan_task task = task_queue[queue_front++];
    pthread_mutex_unlock(&mutex);
    if (queue_rear == (queue_front + 1))
        g_end_server = TRUE;
    return task;
};

void    send_icmp(t_data *dt, t_scan_task *task)
{
    for (int i = 0; i < NFDS; i++) // only one for now
    {
        if (dt->fds[i].revents == 0)
        {
            printf(C_B_RED"[NEED TO RESEND] No revent / unavailable yet"C_RES"\n");
            continue;
        }
        if (dt->fds[i].revents != POLLOUT)
            exit_error_close_socket("Poll unexpected result", dt->socket);
        if (dt->fds[i].fd == dt->socket)
        {
            t_packet packet;
            craft_and_send_icmp(dt->socket, &packet, task);
        }
        else
            warning("Unknown fd is readable.");
    }
}

void    retrieve_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) // args = last arg of pcap_loop
{
    (void)args;
    (void)header;
    ip_h            = (struct iphdr *)          (packet + ETH_H_LEN);                           // packet + 14
    icmp_h          = (struct icmphdr *)        (packet + ETH_H_LEN + IP_H_LEN);                // packet + 14 + 20
    icmp_payload    = (char *)                  (packet + ETH_H_LEN + IP_H_LEN + ICMP_H_LEN);   // packet + 14 + 20 + 8
    // printf(C_G_RED"[QUICK DEBUG] icmp_h->type: %hhu"C_RES"\n", icmp_h->type);
    if (icmp_h->type != ICMP_ECHO_REPLY)
        warning_int("Invalid ICMP type: (bytes)", icmp_h->type);
    else
    {
        printf(C_G_MAGENTA"[INFO]"C_RES" Retrieved packet "C_G_GREEN"[%d]"C_RES"\n", g_retrieve);
        // printf(C_G_MAGENTA"[INFO]"C_RES" Retrieved packet of size "C_G_GREEN"[%d]"C_RES" with type "C_G_GREEN"[%d]"C_RES" and code "C_G_GREEN"[%d]"C_RES"\n", header->len, icmp_h->type, icmp_h->code);
        // printf(C_G_MAGENTA"[INFO]"C_RES"PAYLOAD [%s]\n", icmp_payload);
        g_retrieve++;
    }
}

void    sniff_packets(pcap_t *handle)
{
    printf(C_G_YELLOW"[INFO]"C_RES" Ready to sniff...\n");
    pcap_dispatch(handle, 0, retrieve_packet, NULL);
	print_info("Capture completed");
	pcap_close(handle);
}

void* worker_function(void *dt)
{
    printf(C_B_YELLOW"[NEW THREAD]"C_RES"\n");
    while (g_end_server == FALSE)
    {
        t_scan_task task = dequeue_task();
        print_info_task("Dequeued task", task.id);
        if (task.task_type == SEND)
        {
            if (task.scan_type == ICMP)
            {
                send_icmp((t_data *)dt, &task);
            }
        }
    }
    return NULL;
}

void    init_queue(t_data *dt)
{
    for (int i = 0; i <= g_max_send; i++)
    {
        t_scan_task task;

        task.id              = g_task_id++;
        task.task_type       = SEND;
        task.scan_type       = ICMP;
        task.target_address  = dt->target_address;
        task.dst_port        = dt->dst_port + i;
        enqueue_task(task);
        print_info_task("Enqueued task", task.id);
    }
}

int     main(int ac, char **av)
{
    t_data          dt;
    int             r = 0;
    pcap_t          *handle;

    (void)ac;
    (void)av;
    initialise_data(&dt);
    open_main_socket(&dt);
    // debug_sockaddr_in(&dt.target_address);
    prepare_sniffer(&handle);
    pthread_t       workers[THREADS_NB];
    for (int i = 0; i < THREADS_NB; i++)
    {
        pthread_create(&workers[i], NULL, worker_function, &dt);
    }
    printf(C_B_YELLOW"[MAIN THREAD - START - PRINT NMAP START]"C_RES"\n");
    init_queue(&dt);
    while (g_end_server == FALSE)
    {
        printf(C_G_YELLOW"[INFO]"C_RES" Waiting on poll()...\n");
        r = poll(dt.fds, NFDS, POLL_TIMEOUT);
        if (r < 0)
            exit_error("Poll failure.");
        if (r == 0)
            exit_error("Poll timed out.");
        sniff_packets(handle);
    }
    for (int i = 0; i < THREADS_NB; i++)
    {
        print_info_task("END THREAD", i);
        pthread_join(workers[i], NULL);
    }
    printf(C_B_YELLOW"[MAIN THREAD - END - RETRIEVED %d]"C_RES"\n", g_retrieve);
    close(dt.socket);
    // free_all_malloc();
    return (0);
}