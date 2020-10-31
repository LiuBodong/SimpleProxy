/*
 * simple_proxy.c
 * 
 * this program is a simple proxy
 * 
 * Created on 2020年10月31日 10点32分
 *      
 *      Author: Liubodong
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/unistd.h>
#include <netdb.h>
#include <pthread.h>

#define _DEBUG

typedef struct _request
{
    char method[16];
    char protocol[16];
    char host[256];
    int port;
    char path[1024];
    char http_version[16];
} request;

long long r_b_total = 0L;

int get_line(int *fd, char *buf, int size)
{
    int i = 0;
    char c;
    int n;
    while ((i < size - 1) && ((n = recv(*fd, &c, 1, 0)) > 0))
    {
        buf[i] = c;
        i++;
        if (c == '\n')
        {
            break;
        }
    }
    buf[i + 1] = '\0';
    return i;
}

int parse_http_request(request *req, char *line)
{
    int i = 0;
    char *ptr = line;
    while (ptr && *ptr != '\0')
    {
        if (*ptr == ' ')
        {
            ptr++;
            break;
        }
        req->method[i] = *ptr;
        ptr++;
        i++;
    }
    req->method[i + 1] = '\0';
    i = 0;
    int is_https = 0;
    if (strncasecmp(ptr, "http://", 7) == 0)
    {
        strcpy(req->protocol, "http");
        // 默认80端口
        req->port = 80;
    }
    else if (strncasecmp(ptr, "https://", 8) == 0)
    {
        strcpy(req->protocol, "http");
        // 默认443端口
        req->port = 443;
        is_https = 1;
    }
    else
    {
        return -1;
    }
    ptr += (is_https ? 8 : 7);
    int has_port = 0;
    while (ptr && *ptr != '\0')
    {
        if (*ptr == ':')
        {
            has_port = 1;
            ptr++;
            break;
        }
        if (*ptr == '/')
        {
            break;
        }
        req->host[i] = *ptr;
        ptr++;
        i++;
    }
    req->host[i + 1] = '\0';
    i = 0;
    if (has_port)
    {
        char buf[8];
        while (ptr && *ptr != '\0')
        {
            if (*ptr == '/')
            {
                break;
            }
            buf[i] = *ptr;
            ptr++;
            i++;
        }
        buf[i + 1] = '\0';
        req->port = atoi(buf);
    }
    i = 0;
    while (ptr && *ptr != '\0')
    {
        if (*ptr == ' ')
        {
            ptr++;
            break;
        }
        req->path[i] = *ptr;
        ptr++;
        i++;
    }
    req->path[i + 1] = '\0';
    i = 0;
    while (ptr && *ptr != '\r' && *ptr != '\n' && *ptr != '\0')
    {
        req->http_version[i] = *ptr;
        ptr++;
        i++;
    }
    return 0;
}

void *process_request(void *fd)
{
    int *client_fd = (int *)fd;
    char buf[1024];
    bzero(buf, 1024);
    // 获取第一行数据
    int num_chars = get_line(client_fd, buf, 1024);
    if (num_chars > 0)
    {
#ifdef _DEBUG
        printf("*** %s", buf);
#endif
        // 如果是Connect请求，则返回请求成功
        if (strncasecmp(buf, "CONNECT", 7) == 0)
        {
            char *msg = "HTTP/1.1 200 Connection established";
            send(*client_fd, msg, strlen(msg) + 1, 0);
        }
        else
        {
            // 解析http请求
            request *req = calloc(1, sizeof(request));
            int parse_ret = parse_http_request(req, buf);
#ifdef _DEBUG
            printf("*** method: %s, protocol: %s, host: %s, port: %d, path %s, version: %s\n",
                   req->method, req->protocol, req->host, req->port, req->path, req->http_version);
#endif
            if (parse_ret == 0)
            {
                struct sockaddr_in proxy_dest_addr;
                int proxy_dest_addr_len = sizeof(proxy_dest_addr);
                bzero(&proxy_dest_addr, proxy_dest_addr_len);
                proxy_dest_addr.sin_family = AF_INET;
                proxy_dest_addr.sin_port = htons(req->port);
                struct hostent *h = gethostbyname(req->host);
                char *dest_ip = inet_ntoa(*((struct in_addr *)h->h_addr));
#ifdef _DEBUG
                printf("*** dest_ip: %s\n", dest_ip);
#endif
                proxy_dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

                int proxy_des_sock = socket(PF_INET, SOCK_STREAM, 0);
                int conn = connect(proxy_des_sock, (struct sockaddr *)&proxy_dest_addr, proxy_dest_addr_len);
                if (conn != -1)
                {
                    long long r_b = 0L;
                    char *dest_buf = calloc(1024, sizeof(char));
                    sprintf(dest_buf, "%s %s %s\r\n", req->method, req->path, req->http_version);
#ifdef _DEBUG
                    printf("*** Send %s", dest_buf);
#endif
                    send(proxy_des_sock, dest_buf, strlen(dest_buf), 0);
                    free(dest_buf);
                    bzero(buf, 1024);
                    char conten_length = 0;
                    while (get_line(client_fd, buf, 1024) > 0)
                    {
#ifdef _DEBUG
                        printf("*** Send %s", buf);
#endif
                        if (strncasecmp(buf, "Content-Length:", 15) == 0)
                        {
                            conten_length = atoi(&(buf[15]));
                        }
                        send(proxy_des_sock, &buf, strlen(buf), 0);
                        if (strcmp(buf, "\r\n") == 0)
                        {
                            break;
                        }
                        bzero(buf, 1024);
                    }

                    char c;
#ifdef _DEBUG
                    printf("*** Content-Length: %d\n", conten_length);
#endif
                    for (int i = 0; i < conten_length; i++)
                    {
                        if (recv(*client_fd, &c, 1, 0) == 1)
                        {
                            send(proxy_des_sock, &c, 1, 0);
                        }
                    }
#ifdef _DEBUG
                    printf("*** Send finished, Start receive\n");
#endif
                    while (recv(proxy_des_sock, &c, 1, 0) == 1)
                    {
                        r_b++;
                        send(*client_fd, &c, 1, 0);
                    }
                    r_b_total += r_b;
#ifdef _DEBUG
                    printf("*** Recive finished\n");
#endif
                    printf("*** received: %lld, total received: %lld\n", r_b, r_b_total);
                    close(*client_fd);
                    close(proxy_des_sock);
                    printf("*** Close client socket\n");
                    printf("*** Close dest socket\n");
                }
            }
            free(req);
        }
    }
    return (void *)NULL;
}

int server_start(int *port)
{
    int fd = -1;
    struct sockaddr_in addr;

    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        perror("socket");
        exit(-1);
    }

    int server_addr_len = sizeof(addr);
    bzero(&addr, server_addr_len);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(*port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, server_addr_len) < 0)
    {
        perror("bind");
        exit(-1);
    }

    if (listen(fd, 5) < 0)
    {
        perror("listen");
        exit(-1);
    }

    return fd;
}

int main(int argc, char const *argv[])
{
    if (argc < 2)
    {
        printf("no enaugh argument!\n");
        exit(-1);
    }
    int port = atoi(argv[1]);

    int s_fd = -1;

    s_fd = server_start(&port);
    if (s_fd < 0)
    {
        perror("server start");
        exit(-1);
    }
    printf("*** Server started on port: %d\n", port);

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    while (1)
    {
        int client_fd = accept(s_fd, (struct sockaddr *)&client_addr,
                               &client_addr_len);

        char *clien_host = inet_ntoa(client_addr.sin_addr);
        printf("*** Accept from: %s, port: %d\n", clien_host, client_addr.sin_port);
        if (client_fd == -1)
        {
            perror("accept");
            exit(-1);
        }

        // pthread_t t;
        // if (pthread_create(&t, NULL, process_request, (void *)&client_fd) != -1)
        // {
        //     pthread_detach(t);
        // }
        process_request(&client_fd);
    }

    close(s_fd);
    return 0;
}
