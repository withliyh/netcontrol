#ifndef __CALLCMD_H__
#define __CALLCMD_H__

#include <stdlib.h>
#include "list.h"

typedef struct output { 
    struct list_head list;
    char *line;
}output;


int get_iptables(output **list);
int del_iptables_by_num(int n, output **list);
int del_iptables_by_filter(char* s, char* d, char* p, char* j, output **list);
int post_iptables(const char* s, const char* d, const char* p, const char* j, output **list);

#endif
