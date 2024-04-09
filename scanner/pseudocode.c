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



    // parsing
        // hosts list
        // ports list
        // scans list
        // threads nb

    // each host                    // I suggest to simply handle hosts 1 by 1 (vs. tangled hosts), at least for now
        // resolve_domain()
        // resolve_address()
        // check reachability()

        // init_main_socket()
            // socket()
            // setsockopt()
            // bind_socket_to_src_port()
                // init sockaddr with src_port
                // bind()

        // create_workers()
            // pthread_t workers[threads_nb];
        // each thread
        //      pthread_create(&workers[i], ..., scanner, ...)
    // init_socket_listener()
        // struct pollfd fds[SOCKETS_NB];                       // how to pick SOCKETS_NB?
        // add_main_socket()
        // add_other_sockets()                                  // [UNSURE]

    // craft_scans_tasks()
        // while(1)
            // poll(fds, SOCKETS_NB, timeout)
            // for (int i = 0; i < SOCKETS_NB; i++)
            //    if available fd (fds[i].revents & POLLIN)
            //        task = create_task()
            //        enqueue_task(task)

    // wait_workers_end()
        // each thread
        //      pthread_join(workers[i], NULL)

    // - - - - - - -
    // scanner()
        // while(1)
            // task = dequeue_task()
            // execute_scan_task(task)


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

