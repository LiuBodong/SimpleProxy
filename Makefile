CC=gcc

simple_http_proxy: simple_http_proxy.c
	$(CC) -g -Wall -o $@ $^

clean:
	rm -rf simple_http_proxy