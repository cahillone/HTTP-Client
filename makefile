# Chad Cahill
# EECE 598, California State University - Chico
# Spring 2014

tcp_client: tcp_client.c tcp_general.c tcp_general.h
	gcc tcp_client.c tcp_general.c -o tcp_client -lpcap -Wall -g

clean:
	rm tcp_client
