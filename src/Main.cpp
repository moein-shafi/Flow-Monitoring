#include <iostream>
#include <set>
#include <unordered_map>
#include <vector>

#include <pcap.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include <netinet/ip.h>     // Provides declarations for ip header
#include <net/ethernet.h>       // Provides declarations for ether header
#include <netinet/tcp.h>        // Provides declarations for tcp header

#include "Flow.h"
#include "writer/CSVWriter.h"

#define OUTPUT_FILE "output_file.csv"
#define TIMEOUT 0
#define PROMISC 1
#define SNAP_LEN 65536

using namespace std;

void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
string get_protocol_name(int id);
void create_or_update_flow(string source_ip,
                           string dest_ip,
                           int source_port,
                           int dest_port,
                           string protocol,
                           int64_t total_bytes,
                           int64_t headers_bytes,
                           struct timeval time_stamp,
                           bool finish);
void add_to_finished_flow_list(string key);

unordered_map<string, Flow> ongoing_flows;
vector<Flow> finished_flows;

/**
 * Handles the ending of the program. It will write flows (that are in a finished state) to a CSV file.
 *
 * @param signal_num Alerted signal.
 */
void signal_handler(int signal_num)
{
    CSVWriter csv_writer;
    csv_writer.write(finished_flows, OUTPUT_FILE);
    exit(signal_num);  
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(argc != 2)
    {
        cout << "usage: %s interface_name\n" << argv[0];
        exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(argv[1], SNAP_LEN, PROMISC, TIMEOUT, errbuf);
    if (handle == NULL)
    {
	    cout << "Couldn't open device \n" << argv[1] << ": " << errbuf << endl;
        exit(EXIT_FAILURE);
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0)
    {
        cout << "pcap_loop() failed: " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}

/// Reads each packet, and decides to create or update a flow.
void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer)
{
    const struct ether_header* ether_hdr = (struct ether_header*)buffer;
    const struct iphdr* ip_hdr;
    int source_port, dest_port;
    struct sockaddr_in source_ip, dest_ip;
    bool finish = false;
    int64_t total_bytes = header->len;
    int64_t headers_bytes = sizeof(struct ether_header);

    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP)
    {
        ip_hdr = (struct iphdr*)(buffer + sizeof(struct ether_header));
        headers_bytes += sizeof(struct iphdr);

        source_ip.sin_addr.s_addr = ip_hdr->saddr;
        dest_ip.sin_addr.s_addr = ip_hdr->daddr;

        if (ip_hdr->protocol == IPPROTO_TCP)
        {
            const struct tcphdr* tcp_hdr = (struct tcphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
            headers_bytes += sizeof(struct tcphdr);
            source_port = ntohs(tcp_hdr->source);
            dest_port = ntohs(tcp_hdr->dest);
            if (tcp_hdr->fin == 1)
                finish = true;
        }

        create_or_update_flow(inet_ntoa(source_ip.sin_addr),
                              inet_ntoa(dest_ip.sin_addr),
                              source_port,
                              dest_port,
                              get_protocol_name(ip_hdr->protocol),
                              total_bytes,
                              headers_bytes,
                              header->ts,
                              finish);

    }
}

/**
 * Moves a flow from ongoing_flows list to finished_flow list.
 *
 * @param key Key of the specified flow in ongoing_flows list.
 */
void add_to_finished_flow_list(string key)
{
    finished_flows.push_back(ongoing_flows[key]);
    ongoing_flows.erase(key);
}

/**
 * Based on the existence of a key in ongoing_flows list, it decides to create or update a flow.
 *
 * @param source_ip Source IP address of the packet.
 * @param dest_ip Destination IP address of the packet.
 * @param protocol Protocol of the packet (after IP protocol).
 * @param total_bytes Size of the packet.
 * @param headers_bytes Size of the header of the packet.
 * @param time_stamp Arrived time of the packet.
 * @param finish Value of FIN flag in the packet.
 */
void create_or_update_flow(string source_ip,
                           string dest_ip,
                           int source_port,
                           int dest_port,
                           string protocol,
                           int64_t total_bytes,
                           int64_t headers_bytes,
                           struct timeval time_stamp,
                           bool finish)
{
    string key = source_ip + dest_ip;
    string key_backward = dest_ip + source_ip;
    if (ongoing_flows.find(key) != ongoing_flows.end())
    {
        ongoing_flows[key].add_packet(source_ip,
                                      dest_ip,
                                      protocol,
                                      total_bytes,
                                      headers_bytes,
                                      time_stamp,
                                      finish);

        if (ongoing_flows[key].is_finished())
            add_to_finished_flow_list(key);
    }
    else
    {
        if (ongoing_flows.find(key_backward) != ongoing_flows.end())
        {
            ongoing_flows[key_backward].add_packet(source_ip,
                                                   dest_ip,
                                                   protocol,
                                                   total_bytes,
                                                   headers_bytes,
                                                   time_stamp,
                                                   finish);

            if (ongoing_flows[key_backward].is_finished())
                add_to_finished_flow_list(key_backward);
        }
        else
            ongoing_flows[key] = Flow(source_ip,
                                      dest_ip,
                                      source_port,
                                      dest_port,
                                      time_stamp,
                                      total_bytes,
                                      headers_bytes);
    }
}

/**
 * Returns a name of a specified protocol.
 *
 * @param signal_num Protocol's defined id.
 *
 * @return signal_num Protocol's name.
 */
string get_protocol_name(int id)
{
    switch (id)
    {
        case IPPROTO_ICMP:
            return "ICMP";

        case IPPROTO_IGMP:
            return "IGMP";

        case IPPROTO_IPIP:
            return "IPIP";

        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_EGP:
            return "EGP";

        case IPPROTO_PUP:
            return "PUP";

        case IPPROTO_UDP:
            return "UDP";

        case IPPROTO_IDP:
            return "IDP";

        case IPPROTO_TP:
            return "TP";

        case IPPROTO_DCCP:
            return "DCCP";

        case IPPROTO_IPV6:
            return "IPV6";

        case IPPROTO_RSVP:
            return "RSVP";

        case IPPROTO_GRE:
            return "GRE";

        case IPPROTO_ESP:
            return "ESP";

        case IPPROTO_AH:
            return "AH";

        case IPPROTO_MTP:
            return "MTP";

        case IPPROTO_BEETPH:
            return "BEETPH";

        case IPPROTO_ENCAP:
            return "ENCAP";

        case IPPROTO_PIM:
            return "PIM";

        case IPPROTO_COMP:
            return "COMP";

        case IPPROTO_SCTP:
            return "SCTP";

        case IPPROTO_UDPLITE:
            return "UDPLITE";

        case IPPROTO_MPLS:
            return "MPLS";

        case IPPROTO_RAW:
            return "RAW";

        case IPPROTO_ICMPV6:
            return "ICMPV6";

        default:
            return "Unknown";
    }
}
