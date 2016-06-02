/**
 * 
 * Ulfius Framework example program
 * 
 * This example program describes the main features 
 * that are available in a callback function
 * 
 * Copyright 2015 Nicolas Mora <mail@babelouest.org>
 * 
 * License MIT
 *
 */

#include <string.h>
#include <jansson.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ulfius.h"
#include "parse.h"
#include "callcmd.h"

#define PORT 4100
#define PREFIXRULES "/api/rules"

static json_t *error_reason_response(int code, char* reason);

/**
 * 获取 forward 表的内容
 */
int callback_get_forward(const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_post_forward(const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_del_forward(const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data);

/**
 * decode a u_map into a string
 */
char * print_map(const struct _u_map * map) {
  char * line, * to_return = NULL;
  const char **keys, * value;
  int len, i;
  if (map != NULL) {
    keys = u_map_enum_keys(map);
    for (i=0; keys[i] != NULL; i++) {
      value = u_map_get(map, keys[i]);
      len = snprintf(NULL, 0, "key is %s, value is %s", keys[i], value);
      line = malloc((len+1)*sizeof(char));
      snprintf(line, (len+1), "key is %s, value is %s", keys[i], value);
      if (to_return != NULL) {
        len = strlen(to_return) + strlen(line) + 1;
        to_return = realloc(to_return, (len+1)*sizeof(char));
        if (strlen(to_return) > 0) {
          strcat(to_return, "\n");
        }
      } else {
                to_return = malloc((strlen(line) + 1)*sizeof(char));
                to_return[0] = 0;
      }
      strcat(to_return, line);
      free(line);
    }
    return to_return;
  } else {
    return NULL;
  }
}

char * read_file(const char * filename) {
  char * buffer = NULL;
  long length;
  FILE * f = fopen (filename, "rb");
  if (filename != NULL) {

    if (f) {
      fseek (f, 0, SEEK_END);
      length = ftell (f);
      fseek (f, 0, SEEK_SET);
      buffer = malloc (length + 1);
      if (buffer) {
        fread (buffer, 1, length, f);
      }
      buffer[length] = '\0';
      fclose (f);
    }
    return buffer;
  } else {
    return NULL;
  }
}

int main (int argc, char **argv) {
  int ret;
  
  // Set the framework port number
  struct _u_instance instance;
  
  y_init_logs("simple_example", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting simple_example");
  
  if (ulfius_init_instance(&instance, PORT, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error ulfius_init_instance, abort");
    return(1);
  }
  
  u_map_put(instance.default_headers, "Access-Control-Allow-Origin", "*");
  
  
  // Endpoint list declaration
  ulfius_add_endpoint_by_val(&instance, "POST", PREFIXRULES, "/forward/del", NULL, NULL, NULL, &callback_del_forward, NULL);
  ulfius_add_endpoint_by_val(&instance, "GET", PREFIXRULES, "/forward/:num", NULL, NULL, NULL, &callback_del_forward, NULL);
  ulfius_add_endpoint_by_val(&instance, "DELETE", PREFIXRULES, "/forward/:num", NULL, NULL, NULL, &callback_del_forward, NULL);
  ulfius_add_endpoint_by_val(&instance, "GET", PREFIXRULES, "/forward", NULL, NULL, NULL, &callback_get_forward, NULL);
  ulfius_add_endpoint_by_val(&instance, "POST", PREFIXRULES, "/forward", NULL, NULL, NULL, &callback_post_forward, NULL);
  
  // default_endpoint declaration
  ulfius_set_default_endpoint(&instance, NULL, NULL, NULL, &callback_default, NULL);
  
  // Start the framework
  if (argc == 4 && strcmp("-secure", argv[1]) == 0) {
    // If command-line options are -secure <key_file> <cert_file>, then open an https connection
    char * key_pem = read_file(argv[2]), * cert_pem = read_file(argv[3]);
    ret = ulfius_start_secure_framework(&instance, key_pem, cert_pem);
    free(key_pem);
    free(cert_pem);
  } else {
    // Open an http connection
    ret = ulfius_start_framework(&instance);
  }
  
  if (ret == U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Start %sframework on port %d", ((argc == 4 && strcmp("-secure", argv[1]) == 0)?"secure ":""), instance.port);
    
    // Wait for the user to press <enter> on the console to quit the application
    getchar();
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Error starting framework");
  }
  y_log_message(Y_LOG_LEVEL_DEBUG, "End framework");
  
  y_close_logs();
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  
  return 0;
}

static json_t *error_reason_response(int code, char* reason)
{
    json_t *json = json_object();
    json_object_set_new(json, "code" , json_integer(code));
    json_object_set_new(json, "reason", json_string(reason));
    return json;
}

/**
 * 获取 forward 表的内容
 */
int callback_get_forward(const struct _u_request * request, struct _u_response * response, void * user_data)
{

    json_t *json = parse_get_iptables();
    if (json == NULL) {
        response->json_body = error_reason_response(-1, "internal error occurred.");
        response->status = 400;
    } else {
        response->status = 201;
        response->json_body = json;
    }

    return U_OK;
}



/**
 * 建立 forward 表规则
 */
int callback_post_forward(const struct _u_request * request, struct _u_response * response, void * user_data)
{
    response->status = 400;
    if (request->json_has_error) {
        json_error_t *error = request->json_error;
        response->json_body = error_reason_response(-1, error->text);
        return U_OK;
    }

    json_t *rules = json_object_get(request->json_body, "rules");
    if (rules == NULL) {
        response->json_body = error_reason_response(-1, "cant find key: rules");
        return U_OK;
    }

    size_t rules_num = json_array_size(rules);
    if (rules_num == 0) {
        response->json_body = error_reason_response(-1, "find key rules but not find rule");
        return U_OK;
    }

    size_t index;
    json_t *rule;
    const char *s, *d, *p, *j;
    const char *ns, *nd;

    for (index=0; (index< json_array_size(rules)) && (rule = json_array_get(rules, index)); index++) {
        json_t *s_json = json_object_get(rule, "s");
        s = json_string_value(s_json);

        json_t *d_json = json_object_get(rule, "d");
        d = json_string_value(d_json);
        
        json_t *p_json = json_object_get(rule, "p");
        p = json_string_value(p_json);

        json_t *j_json = json_object_get(rule, "j");
        j = json_string_value(j_json);

	json_t *nd_json = json_object_get(rule, "nd");
	nd = json_string_value(nd_json);
	

        output *output_list;
        int r = post_iptables(s, d, p, j, nd, &output_list);
        if (r != 0) {
            char reason_buf[1024];
            char *reason;
            struct list_head *pos, *n;

            memset(reason_buf, 0, 1024);
            list_for_each_safe(pos, n, &output_list->list) {
                output *entry= list_entry(pos, output, list);
                strcat(reason_buf, entry->line);
            }
            reason = strdup(reason_buf);
            response->json_body = error_reason_response(r, reason != NULL ? reason : "");
            response->status = 400;
            return U_OK;
        }
    }

    response->json_body = error_reason_response(0, "success");
    response->status = 201;
    return U_OK;
}

int callback_del_forward(const struct _u_request * request, struct _u_response * response, void * user_data)
{
    response->status = 400;
    const char *str_num = u_map_get(request->map_url, "num");
    if (str_num != NULL) {
        int num = atoi(str_num); 

        output *output_list;
        int r = del_iptables_by_num(num, &output_list);
        if (r != 0) {
            char reason_buf[1024];
            char *reason;
            struct list_head *pos, *n;

            memset(reason_buf, 0, 1024);
            list_for_each_safe(pos, n, &output_list->list) {
                output *entry= list_entry(pos, output, list);
                strcat(reason_buf, entry->line);
            }
            reason = strdup(reason_buf);
            response->json_body = error_reason_response(r, reason != NULL ? reason : "");
            response->status = 400;
            return U_OK;
        } else {
            response->json_body = error_reason_response(0, "success");
            response->status = 201;
            return U_OK;
        }
    }

    if (request->json_has_error) {
        json_error_t *error = request->json_error;
        response->json_body = error_reason_response(-1, error->text);
        return U_OK;
    }

    json_t *rules = json_object_get(request->json_body, "rules");
    if (rules == NULL) {
        response->json_body = error_reason_response(-1, "cant find key: rules");
        return U_OK;
    }

    size_t rules_num = json_array_size(rules);
    if (rules_num == 0) {
        response->json_body = error_reason_response(-1, "find key rules but not find rule");
        return U_OK;
    }

    size_t index;
    json_t *rule;
    const char *s, *d, *p, *j;
    const char *ns, *nd;

    for (index=0; (index< json_array_size(rules)) && (rule = json_array_get(rules, index)); index++) {
        json_t *s_json = json_object_get(rule, "s");
        s = json_string_value(s_json);

        json_t *d_json = json_object_get(rule, "d");
        d = json_string_value(d_json);
        
        json_t *p_json = json_object_get(rule, "p");
        p = json_string_value(p_json);

        json_t *j_json = json_object_get(rule, "j");
        j = json_string_value(j_json);

	json_t *nd_json = json_object_get(rule, "nd");
	nd = json_string_value(nd_json);

        output *output_list;
        int r = del_iptables_by_filter(s, d, p, j, nd, &output_list);
        if (r != 0) {
            char reason_buf[1024];
            char *reason;
            struct list_head *pos, *n;

            memset(reason_buf, 0, 1024);
            list_for_each_safe(pos, n, &output_list->list) {
                output *entry= list_entry(pos, output, list);
                strcat(reason_buf, entry->line);
            }
            reason = strdup(reason_buf);
            response->json_body = error_reason_response(r, reason != NULL ? reason : "");
            response->status = 400;
            return U_OK;
        }
    }

    response->json_body = error_reason_response(0, "success");
    response->status = 201;

    return U_OK;
}

/**
 * Default callback function called if no endpoint has a match
 */
int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data) {
  response->string_body = strdup("Page not found, do what you want");
  response->status = 404;
  return U_OK;
}
