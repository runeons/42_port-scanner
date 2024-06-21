#include "../includes/ft_nmap.h"

extern pthread_mutex_t mutex;

void        init_handle(t_sniffer *sniffer)
{
    struct bpf_program  compiled_filter;
    char                err_buf[PCAP_ERRBUF_SIZE];          // 256 from pcap.h
    bpf_u_int32         dev_mask;		                    // The netmask of our sniffing device
    bpf_u_int32         net_mask;		                    // The IP of our sniffing device   

    ft_memset(err_buf, 0, PCAP_ERRBUF_SIZE);
    if (pcap_lookupnet(sniffer->device, &net_mask, &dev_mask, err_buf) == -1) // get network mask needed for the filter
    {
        warning("No network mask for device %s\n.", sniffer->device);
        net_mask = 0;
        dev_mask = 0;
    }
    debug_net_mask(net_mask, dev_mask);
    sniffer->handle = NULL;
    if ((sniffer->handle = pcap_open_live(sniffer->device, BUFSIZ, PROMISCUOUS, 1000, err_buf)) == NULL)  // sniff device until error and store it in err_buf
    {
        warning("pcap opening device error %s\n", err_buf);
        exit_error_free("pcap opening device error.\n");
    }
    if (pcap_compile(sniffer->handle, &compiled_filter, sniffer->filter, 0, net_mask) == -1)
    {
        warning("pcap filter %s\n", pcap_geterr(sniffer->handle));
        pcap_freecode(&compiled_filter);
        close_handle(sniffer);
        exit_error_free("pcap filter compilation error.\n");
    }
    if (pcap_setfilter(sniffer->handle, &compiled_filter) == -1)
    {
        warning("pcap filter %s\n", pcap_geterr(sniffer->handle));
        pcap_freecode(&compiled_filter);
        close_handle(sniffer);
        exit_error_free("pcap filter setting error.\n");
    }
    pcap_freecode(&compiled_filter);
}

void        init_sniffer(t_data *dt, t_sniffer *sniffer, char *device)
{
    char    filter[sizeof("src host xxx.xxx.xxx.xxx")];

    sprintf(filter, "src host %s", dt->host.resolved_address);
    if (!(sniffer->device = ft_strdup(device)))
        exit_error_free("malloc failure.\n");
    if (!(sniffer->filter = ft_strdup(filter)))
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
    task->header            = (struct pcap_pkthdr *)header;
    task->packet            = (u_char *)packet;
    enqueue_task(task);
    //pthread_mutex_lock(&mutex);
    g_retrieved++;
    //pthread_mutex_unlock(&mutex);
    debug_task(*task);
}

void        sniff_packets(pcap_t *handle, t_data *dt)
{
    (void)dt;
    info(C_SNIFFER, "Ready to sniff...\n");
    while (g_remaining_scans > 0)
        pcap_dispatch(handle, 0, packet_handler, 0);
    //debug_queue(*dt);
    info(C_SNIFFER, "Capture completed\n");
}
