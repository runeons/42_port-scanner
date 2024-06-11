#include "../includes/ft_nmap.h"

void display_host_init(t_host *host)
{
    
    printf("Nmap scan report for %s (%s)\n", host->input_dest, host->resolved_address);
    //printf("Host is up (0.00035s latency).\n", );
    //printf("Other addresses for google.fr (not scanned): 2a00:1450:4007:819::2003\n", );
    printf("rDNS record for %s: %s\n", host->resolved_address, host->resolved_hostname);
    printf("\n");
}

void display_current_daytime()
{
    struct timeval  tv;
    struct tm       *tm_info;
    char            buffer[32];

    ft_memset(buffer, 0, 32);
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec); // bonus function only
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d %s",
                tm_info->tm_year + 1900,
                tm_info->tm_mon + 1,
                tm_info->tm_mday,
                tm_info->tm_hour,
                tm_info->tm_min,
                tm_info->tm_zone);
    printf("%s\n", buffer);
}

void display_nmap_init(t_data *dt)
{
    (void)dt;
    printf("Starting ft_nmap at ");
    display_current_daytime();
}