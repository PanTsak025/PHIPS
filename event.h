#ifndef __EVENT_H
#define __EVENT_H

enum event_type 
{
    EVENT_EXEC = 1,         //for now event_clone or event_fork is not here 
    EVENT_OPEN = 2,
    EVENT_CONNECT = 3,
    EVENT_EXIT = 4,
};


struct event 
{
    unsigned int type;

    unsigned long long timestamp;
    unsigned int pid;
    unsigned int uid;
    unsigned int ppid;
    char comm[16];

    char filename[128]; // used by event_exec and event_open

    // for event_connect :
    unsigned int remote_addr; // I handle remote sockets for now, local sockets are more comple
    unsigned short remote_port;
    unsigned short family; // AF_INET (=2) or AF_INET6 (=10)

    //for event_exit: nothing needed, pid,uid,comm and timestamp are enough
};

#endif /* __EVENT_H */
