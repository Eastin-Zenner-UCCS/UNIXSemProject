#!/bin/bash

# directory for scrip[t
cd "$(dirname "$0")"

#checks num of arguments and shows usage
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 {encrypt|decrypt} <file_path> <password>"
    exit 1
fi

#run python script
python securefile.py "$@"
