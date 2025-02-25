APP=pcap-sample

all: build run diff
build:
	gcc -o $(APP) pcap-sample.c -lpcap

run:
	./$(APP) sample2.pcapng 

diff:
	diff ftp_data_0.orig cs-test.2.orig 

clean: 
	rm -f ftp*
	rm -f $(APP)
	rm -f *~
