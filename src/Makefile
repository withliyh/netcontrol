CFLAGS=-c -Wall  $(ADDITIONALFLAGS)
LIBS=-lc -lmicrohttpd -ljansson -lcurl
OUTPUT=netcontrol

all: release

netcontrol: netcontrol.o callcmd.o parse.o ulfius.o u_map.o u_request.o u_response.o u_send_request.o yder.o orcania.o
	$(CC) -o $(OUTPUT) netcontrol.o callcmd.o parse.o ulfius.o u_map.o u_request.o u_response.o u_send_request.o yder.o orcania.o  $(LIBS)

netcontrol.o: netcontrol.c
	$(CC) $(CFLAGS) netcontrol.c

parse.o: parse.c
	$(CC) $(CFLAGS) parse.c

callcmd.o: callcmd.c
	$(CC) $(CFLAGS) callcmd.c

yder.o: yder.c
	$(CC) $(CFLAGS) yder.c

orcania.o: orcania.c
	$(CC) $(CFLAGS) orcania.c

ulfius.o: ulfius.h ulfius.c
	$(CC) $(CFLAGS) $(FLAGS_YDER) ulfius.c

u_map.o: ulfius.h u_map.c
	$(CC) $(CFLAGS) $(FLAGS_YDER) u_map.c

u_request.o: ulfius.h u_request.c
	$(CC) $(CFLAGS) $(FLAGS_YDER) u_request.c

u_response.o: ulfius.h u_response.c
	$(CC) $(CFLAGS) $(FLAGS_YDER) u_response.c

u_send_request.o: ulfius.h u_send_request.c
	$(CC) $(CFLAGS) $(FLAGS_YDER) u_send_request.c

clean:
	rm -f *.o *.so $(OUTPUT) 

install:


debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: netcontrol

release: ADDITIONALFLAGS=-O3

release: netcontrol
