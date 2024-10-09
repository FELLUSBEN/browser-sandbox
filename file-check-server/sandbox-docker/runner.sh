#!/bin/bash

grep_files=("informational.sh" "low.sh" "meduim.sh" "high.sh" "critical.sh")

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


path="/app/passwords.txt"

last_access_time=$(stat -c %X "$path")
current_time=$(date +%s)

# Calculate the time difference
time_diff=$((current_time - last_access_time))

if [ $time_diff -le 29 ]; then
    result="malicous"
fi



for script in "${bash_files[@]}"; do
        output=$("./$script")

        if [[ -n "$output" ]]; then
          result="malicious"
        fi
done                                    

if [ "$result" == "malicious" ]; then
  echo "The executable is malicious and has been terminated."
  exit 0
else
  echo "The executable is benign and has been run."
fi
