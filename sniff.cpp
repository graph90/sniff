// Network sniffer
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

void packetHandler(u_char *userData, const struct pcap_pkthdr* packetheader, const u_char* packet){
    std::cout<< "got a packet"<< std::endl;
}


int main(int argv, char** args){
    char errBuf[PCAP_BUF_SIZE];
    //First step: step a connection using a network device
    pcap_if_t* first_device;
    pcap_findalldevs(&first_Device, errBuf);
    if(first_Device == NULL){
        std::cerr << "count not find device" << errBuf << std::endl;
    }
    for (auto current_device = first_device; current_device; current_device=current_device->next;){
        std::cout<< current_device->name<< std::endl;
    }
    auto handle = pcap_create("en0", errBuf);
    pcap_set_promisc(handle, PCAP_OPENFLAG_PROMISCUOUS);
    pcap_set_timeout(handle, 1);
    pcap_set_immediate_mode(handle, 1);
    auto err = pcap_activate(handle);
    pcap_loop(handle, 0, packet_handler, NULL);
}
