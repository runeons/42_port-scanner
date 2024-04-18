#include "ft_nmap.h"

pthread_mutex_t mutex       = PTHREAD_MUTEX_INITIALIZER;

void    enqueue_task(t_data *dt, t_task *task)
{
    pthread_mutex_lock(&mutex);
    ft_lst_add_node_back(&dt->queue, ft_lst_create_node(task));
    print_info_task("Enqueued task", task->id);
    g_queued++;
    pthread_mutex_unlock(&mutex);
}

t_task *dequeue_task(t_data *dt)
{
    pthread_mutex_lock(&mutex);
    t_lst       *first_node = NULL;
    t_task      *task = NULL;

    if (dt->queue == NULL || ft_lst_size(dt->queue) == 1)
        return NULL;
    first_node = ft_lst_get_first_node(&dt->queue);
    if (first_node)
    {
        task = first_node->content;
        ft_lst_remove_node(&dt->queue, first_node);
    }
    else
        return NULL;  
    pthread_mutex_unlock(&mutex);
    return task;
};

t_task    *fill_task(t_task *task, struct sockaddr_in target_address, int dst_port, e_task_type task_type, e_scan_type scan_type)
{
    task->id                = g_task_id++;
    task->task_type         = task_type;
    task->scan_type         = scan_type;
    task->dst_port          = dst_port;
    task->target_address    = target_address;
    return task;
}

t_task    *create_task(int socket)
{
    t_task *task = NULL;

    task = mmalloc(sizeof(t_task));
    if (task == NULL)
        exit_error_close_socket("ft_nmap: malloc failure.", socket);
    task->id                = 0;
    task->task_type         = T_EMPTY;
    task->scan_type         = UNKNOWN;
    task->dst_port          = 0;
    ft_memset(&(task->target_address), 0, sizeof(struct sockaddr_in));
    return task;
}

void init_queue(t_data *dt, t_host *host)
{
    t_lst *curr_port = host->ports;
    while (curr_port != NULL)
    {
        t_port *port = (t_port *)curr_port->content;
        for (int i = 0; i < g_scans_nb; i++)
        {
            t_scan_tracker  *curr_tracker = &(port->scan_trackers[i]);
            t_task          *task = create_task(dt->socket);
            fill_task(task, host->target_address, port->port_id, T_SEND, curr_tracker->scan.scan_type);
            enqueue_task(dt, task);
            debug_task(*task);
        }
        curr_port = curr_port->next;
    }
}