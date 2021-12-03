#ifndef _FLOW_H_
#define _FLOW_H_

#include <string>
#include <set>

#include <time.h>

#define MY_IP "192.168.43.116"

using namespace std;

class Flow
{
    public:
        Flow() = default;
        Flow(string source_ip,
                string dest_ip,
                unsigned int source_port,
                unsigned int dest_port,
                struct timeval timestamp,
                int64_t total_bytes,
                int64_t headers_bytes);

        /**
         * Adds bytes and protocol to the flow, and changes the flow state
         *
         * @param source_ip Source IP address of the packet.
         * @param dest_ip Destination IP address of the packet.
         * @param protocol Protocol of the packet (after IP protocol).
         * @param total_bytes Size of the packet.
         * @param headers_bytes Size of the header of the packet.
         * @param time_stamp Arrived time of the packet.
         * @param finish Value of FIN flag in the packet.
         */
        void add_packet(string source_ip,
                string dest_ip,
                string protocol,
                int64_t total_bytes,
                int64_t headers_bytes,
                struct timeval time_stamp,
                bool finish);

        /// Checks whether flow is in a finished state or not.
        bool is_finished();
        string get_source_ip();
        string get_dest_ip();
        string get_source_port();
        string get_dest_port();
        string get_protocols();
        string get_duration();
        string get_sent_bytes();
        string get_received_bytes();
        string get_headers_bytes_fwd();


    private:
        string source_ip;
        string dest_ip;
        unsigned int source_port;
        unsigned int dest_port;
        set<string> protocols;
        struct timeval start_time;
        struct timeval end_time;
        int64_t sent_bytes;
        int64_t received_bytes;
        int64_t headers_bytes_in_fwd_direction;
        bool forward_finished;
        bool backward_finished;

        /**
         * Decides to add bytes to sent_bytes or received_bytes based on the IP addresses of the packet. Also, adds 
         * headers bytes to headers_bytes_in_fwd_direction.
         *
         * @see add_packet.
         */
        void add_bytes(string source_ip, string dest_ip, int64_t total_bytes, int64_t headers_bytes);

        /**
         * Determines the values of forward_finished and backward_finished, and in the case of being in a finished
         * state, specify the value of end_time of the flow based on the last packet's time_stamp.
         */
        void check_finish_state(string source_ip, string dest_ip, struct timeval time_stamp);
};

#endif
