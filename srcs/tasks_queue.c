#include "../includes/ft_nmap.h"

pthread_mutex_t mutex       = PTHREAD_MUTEX_INITIALIZER;

inline void decr_remaining_scans(int n){
    pthread_mutex_lock(&mutex);
    g_remaining_scans -= n;
    pthread_mutex_unlock(&mutex);
}

void    enqueue_task(t_task *task)
{
    pthread_mutex_lock(&mutex);
    ft_lst_add_node_back(&g_queue, ft_lst_create_node(task));
    info(C_TASKS, "Enqueued task %d\n", task->scan_tracker_id);
    g_queued++;
    pthread_mutex_unlock(&mutex);
}

t_task *dequeue_task()
{
    pthread_mutex_lock(&mutex);
    t_lst       *first_node = NULL;
    t_task      *task = NULL;

    first_node = ft_lst_get_first_node(&g_queue);
    if (first_node)
    {
        task = first_node->content;
        ft_lst_remove_node(&g_queue, first_node);
    }
    pthread_mutex_unlock(&mutex);
    return task;
};

t_task    *fill_send_task(t_task *task, int id, struct sockaddr_in target_address, uint16_t dst_port, e_scan_type scan_type, int socket, int src_ip, uint16_t src_port)
{
    task->socket            = socket;
    task->scan_tracker_id   = id;
    task->src_port          = src_port;
    task->task_type         = T_SEND;
    task->scan_type         = scan_type;
    task->dst_port          = dst_port;
    task->target_address    = target_address;
    task->src_ip            = src_ip;
    return task;
}

t_task    *create_task()
{
    t_task *task = NULL;

    if (!(task = mmalloc(sizeof(t_task))))
        exit_error_free("malloc failure.\n");
    task->scan_tracker_id   = 0;
    task->task_type         = T_EMPTY;
    task->src_port          = 0;
    task->socket            = -1;
    task->scan_type         = UNKNOWN;
    task->dst_port          = 0;
    task->src_ip            = 0;
    task->args              = NULL;
    task->header            = NULL;
    task->packet            = NULL;
    ft_memset(&(task->target_address), 0, sizeof(struct sockaddr_in)); //why not use a pointer ? TO REPLY
    return task;
}

void init_queue(t_data *dt)
{
    int tmp_socket = -1;
    t_lst *curr_port = dt->host.ports;
    int  sock_index = 0;

    while (curr_port != NULL)
    {
        t_port *port = (t_port *)curr_port->content;
        if (port == NULL)
            exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
        for (int i = 0; i < g_scan_types_nb; i++, sock_index++)
        {
            t_scan_tracker  *curr_tracker = &(port->scan_trackers[i]);
            if (curr_tracker == NULL)
                exit_error_full_free(dt, "unexpected memory access. Quiting program.\n");
            t_task          *task = create_task();
            tmp_socket = select_socket_from_pool(dt, curr_tracker->scan.scan_type, sock_index);

            fill_send_task(task, curr_tracker->id, dt->host.target_address, port->port_id, curr_tracker->scan.scan_type, tmp_socket, dt->src_ip, curr_tracker->src_port);
            enqueue_task(task);
            debug_task(*task);
            g_remaining_scans++;
        }
        curr_port = curr_port->next;
    }
}