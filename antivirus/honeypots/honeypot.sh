#!/bin/bash

path="/app/passwords.txt"

honeypot() {
    last_access_time=$(stat -c %X "$path")
    current_time=$(date +%s)

    # Calculate the time difference
    time_diff=$((current_time - last_access_time))

    if [ $time_diff -le 29 ]; then
        echo "The honeypot has been accessed!"
    fi
}

honeypot
