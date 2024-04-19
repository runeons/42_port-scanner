#include "ft_nmap.h"

pthread_mutex_t mutex       = PTHREAD_MUTEX_INITIALIZER;

void    enqueue_task(t_task *task)
{
    pthread_mutex_lock(&mutex);
    ft_lst_add_node_back(&g_queue, ft_lst_create_node(task));
    print_info_task("Enqueued task", task->scan_tracker_id);
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

t_task    *fill_send_task(t_task *task, int id, struct sockaddr_in target_address, int dst_port, e_scan_type scan_type)
{
    task->scan_tracker_id   = id;
    task->task_type         = T_SEND;
    task->scan_type         = scan_type;
    task->dst_port          = dst_port;
    task->target_address    = target_address;
    return task;
}

t_task    *create_task()
{
    t_task *task = NULL;

    task = mmalloc(sizeof(t_task));
    if (task == NULL)
        exit_error_close_socket("ft_nmap: malloc failure.", g_socket);
    task->scan_tracker_id   = 0;
    task->task_type         = T_EMPTY;
    task->scan_type         = UNKNOWN;
    task->dst_port          = 0;
    task->args              = NULL;
    task->header            = NULL;
    task->packet            = NULL;
    ft_memset(&(task->target_address), 0, sizeof(struct sockaddr_in));
    return task;
}

void init_queue(t_host *host)
{
    t_lst *curr_port = host->ports;
    while (curr_port != NULL)
    {
        t_port *port = (t_port *)curr_port->content; // TO PROTECT
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker  *curr_tracker = &(port->scan_trackers[i]); // TO PROTECT
            t_task          *task = create_task();
            fill_send_task(task, curr_tracker->id, host->target_address, port->port_id, curr_tracker->scan.scan_type);
            enqueue_task(task);
            debug_task(*task);
            g_remaining_scans++;
        }
        curr_port = curr_port->next;
    }
}