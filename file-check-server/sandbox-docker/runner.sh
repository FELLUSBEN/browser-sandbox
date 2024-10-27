#!/bin/bash

grep_files=("critical.sh" "high.sh" "medium.sh" "low.sh" "informational.sh")

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
    if [ "$result" = "malicious" ]; then
      echo "file is malicious - critical level"
      exit 0
    fi
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
    result="malicious"
fi
# #shahaf code...........
# file_path="/mnt/pid.txt"
# file_content=""
# file_path_new_logs="/mnt/newlogs.txt"
# if [ -f "$file_path" ]; then
#    file_content=$(cat "$file_path")
# else
#    echo "File does not exist."
# fi
ausearch -ts $(date --date '40 seconds ago' +"%m/%d/%Y") -ts $(date --date '40 seconds ago' +"%H:%M:%S") > /var/log/audit/audit.log
# #shahaf code ...........
echo "fine for now"
for script in "${grep_files[@]}"; do
        output=$(./$script)
        
        echo "check ${script}"
        echo "${output}"
        if [[ -n "$output" ]]; then
          # result="malicious"
          echo "malicious-${script}"
          exit 0
        fi
done                                   

if [ "$result" == "malicious" ]; then
  echo "The executable is malicious and has been terminated."
  exit 0
else
  echo "The executable is benign and has been run."
fi
