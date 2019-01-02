all: clean
	gcc -g proto_proxy_server.c proxy_proto_c/proxy_ptc.c -o server 

clean:
	rm -rf server
