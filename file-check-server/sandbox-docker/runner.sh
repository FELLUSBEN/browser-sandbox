#!/bin/bash

check_malicious() {
    local executable="$1"
    local result=$(python3 /app/malicious_check.py "$executable")
    echo "$result"
}

if [ -z "$1" ]; then
  echo "No executable file specified."
  exit 0
fi

file_type=$(file -b --mime-type "$1")

case $file_type in
  application/x-pie-executable)
    echo "Checking binary executable: $1"
    chmod +x "$1" 
    result=$(check_malicious "$1")
    ;;
  *)
    echo "Unsupported file type: $file_type"
    exit 0
    ;;
esac

if [ "$result" == "malicious" ]; then
  echo "The executable is malicious and has been terminated."
  exit 0
else
  echo "The executable is benign and has been run."
fi
