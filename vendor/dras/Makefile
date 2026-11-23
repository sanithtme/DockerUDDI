all: dras drasraw
CFLAGS= -O3 -Wall -W -Wmissing-prototypes -Wno-main -Wno-unused-parameter -Wno-unused-value -Wno-sign-compare -Wno-implicit-fallthrough
dras: dras.o rawnet.o
drasraw: dras
dras.o: dhcp.h dras.h dras.c
rawnet.o: rawnet.c
dras: 
	gcc ${CFLAGS} -o dras  dras.o rawnet.o
drasraw:
	ln -f dras drasraw
.c.o:
	${CC} ${CFLAGS} -c $<
clean:
	rm -f dras drasraw *.o
