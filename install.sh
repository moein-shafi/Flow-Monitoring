#!/bin/bash

rm -rf Release
mkdir Release
cd Release
cmake ..
make -j
