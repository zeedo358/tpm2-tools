#!/bin/bash
# this script requires root permissions
TEST_FILES=('8bytes.txt' '16bytes.txt' '32bytes.txt' '64bytes.txt' '128bytes.txt' '200bytes.txt' '245bytes.txt')

for test_file in "${TEST_FILES[@]}"
do
    echo "File: $test_file"
    for (( i = 1; i <= 100; i++ ))
    do
        tpm2_rsaencrypt -c key.ctx -o msg.enc $test_file > output.txt 2>&1
        cat output.txt | grep "INFO: Elapsed time (ms):" | awk '{print $5}'
    done
done
