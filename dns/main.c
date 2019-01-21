#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>


#include "protocols.c"
#include "utils.c"


void printDNS(u_char* args, 
	const struct pcap_pkthdr *header,
	const u_char *packet){


	time_t current_time = header->ts.tv_sec;
	struct tm* time_info;
	char timeString[20]; 
	// time(&current_time);
	time_info = localtime(&current_time);
	strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", time_info);


	u_char* fn = (FILE*) args;
	FILE *f = fopen(fn, "a");

	// hexDump("raw packet", packet, header->caplen);
	int offset = 0;

	//skip ethernet
	offset += sizeof(struct ethernet);
	
	struct ip* IP = (struct ip*)(packet + offset);
	int ipVersion = IP_V(IP);
	// printf("ipv%d\n", ipVersion);	
	if (ipVersion == 6){
		offset += 40;
	}else if(ipVersion == 4){
		offset += 20;
	}else{
		printf("invalid IP version\n");
	}

	struct udp* UDP = (struct udp*)(packet + offset);
	// printf("src: %d, dst: %d\n", ntohs(UDP->sport), ntohs(UDP->dport));
	offset += sizeof(struct udp);

	//skip dns header
	offset += sizeof(struct dns);

	offset += 1;
	u_char* query = packet + offset;

	int i=0;	
	while(query[i] != 0){
		if(query[i] < 0x20 || query[i] > 0x7e){
			query[i] = '.';
		}
		i++;
	}


	
	// printf("%s ", timeString);
	printf("%s\n", query);


	query[i] = '\n';
	timeString[19] = ' ';
	fwrite(timeString, sizeof(char), sizeof(timeString), f);
	fwrite(query, sizeof(char), i+1, f);


	fclose(f);

	// printf("==================\n");


}


int main(int argc, char *argv[]){
	char *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "dst port 53";	/* The filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet; /* The actual packet */

	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", device);

	// if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
	// 	fprintf(stderr, "Can't get netmask for device %s\n", device);
	// 	net = 0;
	// 	mask = 0;
	// }
	// struct in_addr net_addr;
 //    net_addr.s_addr = net;
 //    struct in_addr mask_addr;
 //    mask_addr.s_addr = mask;
	// printf("net: %s, mask: %s\n", inet_ntoa(net_addr), inet_ntoa(mask_addr));

	
	pcap_t *handle;
	handle = pcap_open_live(device, BUFSIZ, true, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
		return(2);
	}

	// char raw[] = "this is my own packet";
	// pcap_inject(handle, raw, 22);


	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}


	pcap_loop(handle, 1000, printDNS, "domains.txt");


	// packet = pcap_next(handle, &header);
	// /* Print its length */
	// printf("Jacked a packet with length of [%d]\n", header.len);
	// hexDump("raw packet:", packet, header.caplen);

	// pcap_dumper_t *dumper = pcap_dump_open(handle, "a.pcap");
	// pcap_dump(dumper, &header, packet);
	// // fwrite(packet, sizeof(char), header.caplen, f);
	

	/* And close the session */
	pcap_close(handle);

	
	return(0);
}

