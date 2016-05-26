#include <stdio.h>
#include <string.h>
#include "callcmd.h"
#include "parse.h"

json_t *parse_get_iptables()
{
    json_t *json_rules = json_array();
    output *list;
    int result = get_iptables(&list);
    if (result != 0) {
        //error branch
        return NULL;
    }
    const char *delim = " ";
    struct list_head *pos, *n;
    list_for_each_safe(pos, n, &list->list) {
        output *entry= list_entry(pos, output, list);
        char *line = entry->line;

        char *col_num = strtok(line, delim);

        int num = atoi(col_num);
        if (num < 1) continue;

        json_t *json = json_object();
        json_object_set_new(json, "no", json_integer(num));

        char *col_target = strtok(NULL, delim);
        json_object_set_new(json, "j", json_string(col_target));

        char *col_prot = strtok(NULL, delim);
        json_object_set_new(json, "p", json_string(col_prot));

        char *col_opt = strtok(NULL, delim);
        json_object_set_new(json, "opt", json_string(col_opt));

        char *col_source = strtok(NULL, delim);
        json_object_set_new(json, "s", json_string(col_source));

        char *col_destination = strtok(NULL, delim);
        json_object_set_new(json, "d", json_string(col_destination));

        json_array_append_new(json_rules, json);

        free(entry->line);
        free(entry);
    }
    json_t *response_body = json_object();
    json_object_set_new(response_body, "rules", json_rules);
    return response_body;
}

