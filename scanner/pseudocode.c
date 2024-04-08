// pseudocode

// 1 thread / port or 1 thread / port-scan

// each host
    // resolve_domain() [BONUS]
    // resolve_address() [CORE]
    // check reachability / host discovery [BONUS]
    // each port                            // aggregate all scans results in 1 host-port struct
        // resolve_service() [CORE] + version [BONUS]
        // run each scan [CORE]
            // send packets
            // receive packets
            // analyse result
        // port_conclusion() [CORE]
    // OS detection [BONUS]

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// main

// I suggest simply : hosts 1 by 1 (vs. tangled hosts), at least for now

// parsing
    // hosts list
    // ports list
    // scans list
    // threads nb

// init_main_socket()
    // socket()
    // setsockopt()
    // bind_socket_to_src_port()
        // init sockaddr with src_port
        // bind()
// signal(SIGINT, handle_sigint);

// create_workers()
    // pthread_t workers[threads_nb];
    // for (int i = 0; i < threads_nb; i++)
    //      pthread_create(&workers[i], NULL, scanner, NULL);
// init_socket_listener()
    // struct pollfd fds[SOCKETS_NB];
    // add_main_socket()
    // add_other_sockets() [UNSURE]

// listen_loop()
    // while(1)
        // poll(fds, SOCKETS_NB, -1)
        // for (int i = 0; i < SOCKETS_NB; i++)
        //    if (fds[i].revents & POLLIN)
        //        enqueue_task();

// wait_workers_end()
    // for (int i = 0; i < threads_nb; i++)
    //      pthread_join(workers[i], NULL);

// - - - - - - -
// scanner()
    // while(1)
        // task = dequeue_task()
        // execute_task(task)




// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// scans functions
    // initial_handshake()
        // send
            // ICMP (ECHO request)
            // TCP SYN
            // TCP ACK
        // recv
            // TCP RST
            // ICMP (ECHO reply)
            // TCP SYN ACK
    // run_syn_scan()
        // initial_handshake()
        // send TCP SYN ACK
        // rcv
            // TCP RST
            // TCP SYN ACK
            // rien
        // analyse
    // run_ack_scan()
        // initial_handshake()
        // send TCP ACK only
        // rcv
            // TCP SYN
            // ICMP
            // else
        // analyse
    // run_fin_scan()
    // run_null_scan()
    // run_xmas_scan()
        // initial_handshake()
        // send TCP F/N/X
        // rcv
            // TCP RST
            // ICMP
            // else
        // analyse
    // run_udp_scan()
        // initial_handshake()
        // send UDP
        // rcv
            // UDP (rare)
            // ICMP
            // else
        // analyse

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// host struct
    // address
    // domain
    // ports
    // scan_types

// host-port struct
    // host
    // port
    // service
    // scan_types
    // scan_syn          // define ACTIVATED / NON-ACTIVATED then RESULTS
    // scan_ack
    // scan_fin
    // scan_null
    // scan_udp
    // scan_xmas
    // conclusion

// packets structs (inc. bits to read) needed
    // tcp_header
        // URG
        // ACK
        // PSH
        // RST
        // SYN
        // FIN
    // udp_header
    // icmp_header
        // TYPE
        // CODE

