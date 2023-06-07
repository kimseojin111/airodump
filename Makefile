LDLIBS=-lpcap

all: airodump


airodump.o: mac.h airodump.cpp


mac.o : mac.h mac.cpp

airodump: airodump.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o