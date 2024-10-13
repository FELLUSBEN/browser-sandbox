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

COPY low.txt /app/low.sh

COPY medium.txt /app/medium.sh

COPY high.txt /app/high.sh

COPY critical.txt /app/critical.sh

COPY informational.txt /app/informational.sh

COPY malicious_check.py /app/malicious_check.py

COPY passwords.txt /app/passwords.txt

RUN chmod +x /app/runner.sh

COPY audit.rules /etc/audit/rules.d/audit.rules

RUN service auditd restart



ENTRYPOINT ["/app/runner.sh"]
