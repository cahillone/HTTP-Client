# Chad Cahill
# EECE 598, California State University - Chico
# Spring 2014

http_client: http_client.c tcp_general.c tcp_general.h
	gcc http_client.c tcp_general.c -o http_client -lpcap -Wall -g

clean:
	rm http_client
