// clang poc.c && sudo ./a.out -h 1.1.1.1 -t 3

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "arg_parse.h"
#include "data.h"
#include "colors.h"

#define MAX_THREADS 250

int poc_error(const char *s, int sock)
{
    (void)sock;
    printf("%s\n", s);
    exit(1);
    return (1);
}

void *worker(void *thread_opts)     // Be careful, it is void *.
{
	struct thread_opts *opts;       // Create pointer to struct which carries all options passed by main

	opts = thread_opts;             // Now opt will point to thread_opt passed by main
	scanner(opts->host, &opts->port, opts->timeout, &opts->start, &opts->end); // Call a core function will do entire work of scanning
	pthread_exit(NULL);             // Exit current thread
}

int scanner(const char * host, unsigned int *port, unsigned int timeout, unsigned int *start, unsigned int *end)
{
	
	struct sockaddr_in address, bind_addr;      // This struct has all information which is required to connect to target
	struct timeval tv;                          // This struct is used in select(). It contains timeout information.
	fd_set write_fds;
	socklen_t so_error_len;                     // The socket descriptor, error status and yes.
	int sd, so_error = 1, yes = 1;
	int write_permission;
	
	while(!*start)                              // Wait until start flag is not enabled by main process - faire sans avec les mutex ?
		sleep(2);
    while(!*end)                                // Process until end flag is not set by main process
    {
        while(*port == 0)                       // Wait for 2 seconds till port is 0
            sleep(2);

        // Fill sockaddr_in struct and timeout
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = inet_addr(host);	// inet_addr() converts string of host IP to int 
        address.sin_port = htons(*port);	        // htons() returns int with data set as big endian. Most computers follow little endian and network devices only know big endian
        tv.tv_sec = timeout;                        // Seconds to timeout
        tv.tv_usec = 0;                             // Microseconds to timeout

        FD_ZERO(&write_fds);
        so_error_len = sizeof(so_error);
        if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)                       // create socket
            return poc_error("socket() An error has occurred", 0);
        if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)   // Set port as reuseable. So we may not use up all avilable ports
            return poc_error("setsockopt() An error has occured", 0);
        if(fcntl(sd, F_SETFL, O_NONBLOCK) == -1)                                // Make our socket non-blocking. Program will not stop until connection is made
            return poc_error("fcntl() caused error", 1);;
        if (connect(sd, (struct sockaddr *) &address, sizeof(address)) == -1)   // Now connect() function will always returns -1 as we are in non-blocking flag
        {
            switch (errno)
            {
                case EWOULDBLOCK: /* Processing going on */
                case EINPROGRESS: /* Connection in progress */
                    break;
                default:			/* We want to give error on every other case */
                    return poc_error("connect() An error has occurred", sd);
            }
        }
        FD_SET(sd, &write_fds);
        
        if((write_permission = select(sd + 1, NULL, &write_fds, NULL, &tv)) == -1)      // Waiting for time when we can write on socket or timeout occurs
            return poc_error("select() An error has occurred", sd);
        if(write_permission)
            if(getsockopt(sd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != -1)
            {
                if(so_error == 0)
                    printf("%d OPEN\n", *port);
            }
        *port = 0; // Set port to 0. So we do not process one port again and again
    }
    return (0);
}

int main(int argc, char *argv[])
{
	struct arguments    *user_args;

    // parse and init args
	user_args = parse_args(argc, argv);
	if(strlen(user_args->host) == 0)
		poc_error("[-] Please specify host\n", 1);
    struct hostent *target;// Resolve hostname
    target = gethostbyname(user_args->host);
    bzero(user_args->host, strlen(user_args->host));// Copy to struct with typecasting
    strcpy(user_args->host , inet_ntoa(*( (struct in_addr *)target->h_addr_list[0] )));
    printf("Scanning %s\n", user_args->host);

    int                 thread_id;
    pthread_t           threads[MAX_THREADS];
    struct thread_opts  opts[MAX_THREADS]; // tous les threads
    int unsigned        port_scan = 1;
    for (thread_id = 0; thread_id < MAX_THREADS; thread_id++)
    {
        // fill thread opts
        opts[thread_id].start       = 0;	
        opts[thread_id].end         = 0;	
        opts[thread_id].port        = 0;	
        opts[thread_id].timeout     = user_args->timeout;	
        opts[thread_id].thread_id   = thread_id;
        strncpy(opts[thread_id].host, user_args->host, (size_t)INET_ADDRSTRLEN);
        // actually create thread with ioptions
        if (pthread_create(&threads[thread_id], NULL, worker, (void *) &opts[thread_id])) // chaque thread va appeler worker
        {
            perror("pthread_create() error");	/* Print error in thread creation */
            return EXIT_FAILURE;
        }
    }
    thread_id = 0;	
    printf("--> Created %d threads.\n", MAX_THREADS);

    // Loop till over all ports are scanned
    while (port_scan < 1024) // 65535 // for all ports
    {
        /* Iterate through all threads */
        for (int i = 0; i < MAX_THREADS; i++) // for all threads
        {
            // printf(C_G_RED"[QUICK DEBUG] i: %d"C_RES"\n", i);
            if(opts[i].port == 0)
            {
                opts[i].port = port_scan;	 // ds chaque thread, on affecte le numero de port	
                port_scan++;					
                opts[i].start = 1; // et on lui dit de commencer a scanner
            }
        }
    }
}