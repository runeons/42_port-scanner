#include "../includes/ft_nmap.h"

extern pthread_mutex_t mutex;

void        init_handle(t_sniffer *sniffer)
{
    char                err_buf[PCAP_ERRBUF_SIZE];          // 256 from pcap.h

    ft_memset(err_buf, 0, PCAP_ERRBUF_SIZE);
    sniffer->handle = NULL;
    if ((sniffer->handle = pcap_open_live(sniffer->device, BUFSIZ, PROMISCUOUS, 1000, err_buf)) == NULL)  // sniff device until error and store it in err_buf
    {
        // warning("pcap opening device error %s\n", err_buf);
        exit_error_free("pcap opening device error.\n");
    }
}

void        init_sniffer(t_data *dt, t_sniffer *sniffer, char *device)
{
    (void)dt;
    if (!(sniffer->device = ft_strdup(device)))
        exit_error_free("malloc failure.\n");
}

pcap_if_t   *find_devices()
{
    pcap_if_t   *interfaces;
    char        err_buf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&interfaces, err_buf) == -1)
        exit_error_free("Finding devices %s\n", err_buf);
    return interfaces;
}

void        packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) // args = last arg of pcap_loop
{
    t_task  *task = create_task();

    task->scan_tracker_id   = 0; // TO DO
    task->task_type         = T_RECV;
    task->args              = args;
    task->header            = mmalloc(sizeof(struct pcap_pkthdr));
    if (task->header == NULL)
        exit_error_free("malloc failure.\n");

    memcpy(task->header, header, sizeof(struct pcap_pkthdr));
    if (task->header->len)
        return; 
    task->packet            = mmalloc(task->header->len);
    if (task->packet == NULL)
        exit_error_free("malloc failure.\n");
    memcpy(task->packet, packet, task->header->len);

    enqueue_task(task);
    g_retrieved++;
    debug_task(*task);
}

void        sniff_packets(pcap_t *handle, t_data *dt)
{
    (void)dt;
    info(C_SNIFFER, "Ready to sniff...\n");
    while (g_remaining_scans > 0)
        pcap_dispatch(handle, 0, packet_handler, 0);
    info(C_SNIFFER, "Capture completed\n");
}
