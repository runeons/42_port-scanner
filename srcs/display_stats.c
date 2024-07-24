#include "../includes/ft_nmap.h"

void            display_host_init(t_host *host, int no_dns)
{
    printf("Nmap scan report for %s (%s)\n", host->input_dest, host->resolved_address);
    if (no_dns == FALSE)
        printf("rDNS record for %s: %s\n", host->resolved_address, host->resolved_hostname);
    printf("\n");
}

static void     display_current_daytime()
{
    struct timeval  tv;
    struct tm       *tm_info;
    char            buffer[34];

    ft_memset(buffer, 0, 34);
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d %s",
                tm_info->tm_year + 1900,
                tm_info->tm_mon + 1,
                tm_info->tm_mday,
                tm_info->tm_hour,
                tm_info->tm_min,
                tm_info->tm_zone);
    printf("%s\n", buffer);
    // free(tm_info); TO CHECK
}

void            display_nmap_init(t_data *dt)
{
    (void)dt;
    printf("Starting ft_nmap at ");
    display_current_daytime();
}

void            display_nmap_end(t_data *dt)
{
    struct timeval      end_tv;
    struct timeval      tz;
    int                 time = 0;

    if (gettimeofday(&end_tv, &tz) != 0)
        exit_error_full_free(dt, "cannot retrieve time.\n");
    time = (end_tv.tv_sec - dt->init_tv.tv_sec) * 1000000 + end_tv.tv_usec - dt->init_tv.tv_usec;
    printf("Nmap done: %d hosts scanned in %.2f seconds\n", dt->hosts_nb, (float)time / 1000000);
}
