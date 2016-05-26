#include <stdio.h>
#include <string.h>
#include "callcmd.h"

int assert(char *d, int dlen, const char* s)
{
    if (strlen(s) == 0) {
        return 0;
    }
    int l = strlen(s)+strlen(d);
    if (l > dlen) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * 存在严重的安全问题
 */
int call_cmd(char* cmd, output **list)
{
    int result = -1;
    char buf[1024];
    char result_buf[1024];

    snprintf(buf, 1024, "%s", cmd);
    strcat(buf, " 2>&1");//redirect stderr stream to stdout stream

    printf("%s\n", buf);
    FILE *readPipe = popen(buf, "r");
    if (readPipe) {
        if (list != NULL) {
            output *output_list= (output*) malloc(sizeof(output));
            INIT_LIST_HEAD(&output_list->list);
            *list = output_list;

            output *entry = (output*) malloc(sizeof(output));
            entry->line = strdup(cmd);
            list_add_tail(&entry->list, &output_list->list);

            while (fgets(result_buf, 1024, readPipe) != 0) {
                output *entry = (output*) malloc(sizeof(output));
                entry->line = strdup(result_buf);
                list_add_tail(&entry->list, &output_list->list);
            }
        }
        result = pclose(readPipe);
    }
    return result;
}

int get_iptables(output **list)
{
    char buf[1024];
    memset(buf, 0, 1024);
    snprintf(buf, 1024, "iptables -n --line-numbers -t filter -L FORWARD");
    int result = call_cmd(buf, list);
    return result;
}

int del_iptables_by_num(int n, output **list)
{
    char buf[1024];
    memset(buf, 0, 1024);
    snprintf(buf, 1024, "iptables -t filter -D FORWARD %d", n);
    return call_cmd(buf, list);
}

int del_iptables_by_filter(char* s, char* d, char* p, char* j, output **list)
{
    char buf[1024];
    memset(buf, 0, 1024);
    snprintf(buf, 1024, "iptables -t filter -D FORWARD ");
    if (s && assert(buf, 1024, s)) {
        strcat(buf, " -s ");
        strcat(buf, s);
    }
    if (d && assert(buf, 1024, d)) {
        strcat(buf, " -d ");
        strcat(buf, d);
    }
    if (p && assert(buf, 1024, p)) {
        strcat(buf, " -p ");
        strcat(buf, p);
    }
    if (j && assert(buf, 1024, j)) {
        strcat(buf, " -j ");
        strcat(buf, j);
    }
    return call_cmd(buf, list);
}

int post_iptables(const char* s, const char* d, const char* p, const char* j, output **list)
{
    char buf[1024];
    memset(buf, 0, 1024);
    snprintf(buf, 1024, "iptables -t filter -A FORWARD ");
    if (s && assert(buf, 1024, s)) {
        strcat(buf, " -s ");
        strcat(buf, s);
    }
    if (d && assert(buf, 1024, d)) {
        strcat(buf, " -d ");
        strcat(buf, d);
    }
    if (p && assert(buf, 1024, p)) {
        strcat(buf, " -p ");
        strcat(buf, p);
    }
    if (j && assert(buf, 1024, j)) {
        strcat(buf, " -j ");
        strcat(buf, j);
    }
    return call_cmd(buf, list);
}
