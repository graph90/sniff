//Network sniffer
#include <iostream>
#include <pcap.h>

// These are premade ethernet and ip header objects
// in the form of C structs.
#include <netinet/ip.h>
#include <net/ethernet.h>

// If you are on linux, you may need to use:
#include <netinet/if_ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>


// Function to handle incoming packets.
// First argument is user input. It is NULL (seewe the call to pcap_loop)
// Second is a packet header for us to use
// Third is the packet itself in raw bytes
void packet_handler(u_char *user_data, 
    const struct pcap_pkthdr* packet_header, 
    const u_char* packet) {
    //print the ethernet address 
    int i;
    for (i = 0; i < 6; i++) {
        printf("%02x", address[i]);
        if (i != 5) {
            printf(":");
        }
    }
    // Get the IP header from the packet
    struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    // Print out the source and destination addresses && Print out the TTL and flags
    printf("Packet source: %s\n", inet_ntoa(ip_header->ip_src),"Packet destination: %s\n",inet_ntoa(ip_header->ip_dst), "TTL: %d\n", ip_header->ip_ttl, "Flags: %d\n",  ip_header->ip_off);
    // Lets get rid of the ethernet header
    // First we need to convert the packet to an ethernet frame

    // this works because the ether_header lines up with the start of the packet.
    // the format is a standard byte struct
    const struct ether_header* ether;
    ether = (struct ether_header*) packet;
    auto type = ntohs(ether->ether_type);

    // see if this is an IPv4 frame
    if (type == ETHERTYPE_IP) {
        // take off ethernet header
        // this is 14 bytes, remember the slides

        struct ip* ip_header;
        ip_header = (struct ip*) (packet + 14);

        if (ip_header->ip_p == IPPROTO_TCP) {
            std::cout << "got a tcp packet" << std::endl;

            // Strip off IP header, remember we need to multiply the header length by 4.
            // its length is given in words
            // auto header_length = ip_header->ip_hl * 4;
            // auto payload = (u_char*) (packet + header_length);
            //logic for tcp header
            struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            std::cout << "TCP Packet " << ntohs(tcp_header->dest) << std::endl;
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            // will get us ping packets
            //logic for ICMP header
            struct icmphdr *icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            //print
            std::cout << "got a ICMP packet: "<< ntohs(icmp_header->code) << std::endl;
        }else if(ip_header->ip_p == IPPROTO_UDP){
            // auto packet_length = ip_header.ip_hl * 4;
            // auto payload = (u_char*) (packet + packet_length);
            //logic for UDP header
            struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            //print
            std::cout << "Got a UDP packet: " << ntohs(tcp_header->dest) <<std::endl;
        }else if(ip_header->ip_p == IPPROTO_ECHO){
            //logic for Echo header
            struct echo *echo_header = (struct echo*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            //print
            std::cout << "Got a UDP packet: " << ip_header->ip_dst.s_addr <<std::endl;
        }

        // print IP address in decimal notation
        auto addr = (char*) &(ip_header->ip_src);
        // printf("  source: %hhu.%hhu.%hhu.%hhu\n",addr[0], addr[1],addr[2], addr[3]);
        addr = (char*) &(ip_header->ip_dst);
        printf("  destination: %hhu.%hhu.%hhu.%hhu\n",addr[0], addr[1],addr[2], addr[3]);
    }
}

int main(int argv, char** args) {
    char errbuf[PCAP_BUF_SIZE]; // initialize and empty string for errors


    // First step: setup a connection using a network device
    // This is a pointer to the first device, which ha
    s pointers to each
    // subsequent one, making a linked list of them.
    pcap_if_t* first_device;
    
    pcap_findalldevs(&first_device, errbuf); // find all devices, store the first
    if (first_device == NULL) {
        std::cerr << "couldn't find a device" << errbuf << std::endl;
    }

    // iterate from the first to the last device, using next pointers.
    // loop terminates when the current_devices is null
    for (auto current_device = first_device; current_device; current_device = current_device->next) {
        std::cout << current_device->name << std::endl;
    }
    // Use this if you have an ethernet device to work with.
    // auto handle = pcap_create("en0", errbuf);

    // Use this code for files:
    auto file = fopen("smallFlows.pcap", "rb");
    auto handle = pcap_fopen_offline(file, errbuf);
    // Change handler settings

    pcap_set_promisc(handle, PCAP_OPENFLAG_PROMISCUOUS); // set promiscuous mode
    pcap_set_timeout(handle, 1); // set a timeout
    pcap_set_immediate_mode(handle, 1); // give us packets as soon as they come in

    auto err = pcap_activate(handle); // activate handler

    // Filter packets by host, ect
    struct bpf_program fp;
    pcap_compile(handle, &fp, "icmp and host www.google.ca", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    // Start the packet handling loop. This uses a callback function called packet_handler

    // second argument is the count of packets to sniff. 0 will loop forever.
    pcap_loop(handle, 0, packet_handler, NULL); // packet_handler is called with every new packet

}