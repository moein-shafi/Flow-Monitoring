#include "Flow.h"

using namespace std;

Flow::Flow(
        string source_ip,
        string dest_ip,
        unsigned int  source_port,
        unsigned int dest_port,
        struct timeval time_stamp,
        int64_t total_bytes,
        int64_t headers_bytes)
{
    this->source_ip = source_ip;
    this->dest_ip = dest_ip;
    this->source_port = source_port;
    this->dest_port = dest_port;
    this->start_time = time_stamp;
    this->end_time = this->start_time;
    this->received_bytes = 0;
    this->sent_bytes = 0;
    this->headers_bytes_in_fwd_direction = 0;
    this->forward_finished = false;
    this->backward_finished = false;

    this->add_bytes(source_ip, dest_ip, total_bytes, headers_bytes);
}

void Flow::add_bytes(string source_ip, string dest_ip, int64_t total_bytes, int64_t headers_bytes)
{
    if (source_ip == MY_IP)
    {
        this->sent_bytes += total_bytes;
        this->headers_bytes_in_fwd_direction += headers_bytes;
    }
    else if (dest_ip == MY_IP)
        this->received_bytes += total_bytes;
}

void Flow::check_finish_state(string source_ip, string dest_ip, struct timeval time_stamp)
{
    if (source_ip == MY_IP)
        this->forward_finished = true;
    else if (dest_ip == MY_IP)
        this->backward_finished = true;

    if (this->forward_finished && this->backward_finished)
        this->end_time = time_stamp;
}

void Flow::add_packet(
        string source_ip,
        string dest_ip,
        string protocol,
        int64_t total_bytes,
        int64_t headers_bytes,
        struct timeval time_stamp,
        bool finish)
{
    this->add_bytes(source_ip, dest_ip, total_bytes, headers_bytes);
    this->protocols.insert(protocol);

    if (finish)
        this->check_finish_state(source_ip, dest_ip, time_stamp);
}

bool Flow::is_finished()
{
    return (this->forward_finished && this->backward_finished);
}

string Flow::get_source_ip()
{
    return this->source_ip;
}

string Flow::get_dest_ip()
{
    return this->dest_ip;
}

string Flow::get_source_port()
{
    return to_string(this->source_port);
}

string Flow::get_dest_port()
{
    return to_string(this->dest_port);
}

string Flow::get_protocols()
{
    string protocols_string = "";
    for (auto protocol : this->protocols)
    {
        protocols_string += protocol;
        protocols_string += " ";
    }

    return protocols_string;
}

string Flow::get_duration()
{
    float duration = ((this->end_time.tv_sec * 1000000 + this->end_time.tv_usec) -
            (this->start_time.tv_sec * 1000000 + this->start_time.tv_usec));
    return to_string(duration / 1000000);
}

string Flow::get_sent_bytes()
{
    return to_string(this->sent_bytes);
}

string Flow::get_received_bytes()
{
    return to_string(this->received_bytes);
}

string Flow::get_headers_bytes_fwd()
{
    return to_string(this->headers_bytes_in_fwd_direction);
}
