LDLIBS=-lpcap

all: send-arp-test


main.o: util.h mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: util.h mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: util.h mac.h ethhdr.h ethhdr.cpp

util.o: util.h util.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o util.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
