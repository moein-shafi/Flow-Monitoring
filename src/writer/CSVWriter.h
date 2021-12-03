#ifndef _CSVWRITER_H_
#define _CSVWRITER_H_

#include <iostream>
#include <vector>
#include <fstream>

#include "../Flow.h"
#include "Writer.h"

using namespace std;

class CSVWriter: public Writer
{
    public:
        CSVWriter() = default;
        inline void write(vector<Flow> &flows, string file_address)
        {
            std::ofstream output_file;
            output_file.open (file_address);
            output_file << "Source IP, Dest IP, Source Port, Dest Port, Protocols, Duration, Sent Bytes,"
                "Received Bytes, Header Bytes FWD\n";
            for (auto flow : flows)
            {
                output_file << flow.get_source_ip() << ",";
                output_file << flow.get_dest_ip() << ",";
                output_file << flow.get_source_port() << ",";
                output_file << flow.get_dest_port() << ",";
                output_file << flow.get_protocols() << ",";
                output_file << flow.get_duration() << ",";
                output_file << flow.get_sent_bytes() << ",";
                output_file << flow.get_received_bytes() << ",";
                output_file << flow.get_headers_bytes_fwd() << endl;
            }
            output_file.close();
        }
};

#endif
