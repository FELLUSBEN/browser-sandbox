FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    python3-psutil \
    auditd \ 
    file \
    && apt-get clean

#RUN pip3 install psutil

WORKDIR /app

COPY runner.sh /app/runner.sh

COPY libapilog.so /app/libapilog.so

COPY rules_by_level/low.sh /app/low.sh

COPY rules_by_level/medium.sh /app/medium.sh

COPY rules_by_level/high.sh /app/high.sh

COPY rules_by_level/critical.sh /app/critical.sh

COPY rules_by_level/informational.sh /app/informational.sh

COPY malicious_check.py /app/malicious_check.py

COPY passwords.txt /app/passwords.txt

RUN chmod +x /app/runner.sh

COPY audit.rules /etc/audit/rules.d/audit.rules

RUN service auditd restart



ENTRYPOINT ["/app/runner.sh"]
