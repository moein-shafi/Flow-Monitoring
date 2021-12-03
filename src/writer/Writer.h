#ifndef _WRITER_H_
#define _WRITER_H_

#include <vector>

#include "../Flow.h"

using namespace std;

class Writer
{
    public:
        Writer() = default;
        virtual void write(vector<Flow> &flows, string file_address) = 0;
};

#endif
