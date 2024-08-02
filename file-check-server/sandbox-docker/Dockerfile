FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    python3-psutil \
    file \
    && apt-get clean

#RUN pip3 install psutil

WORKDIR /app

COPY runner.sh /app/runner.sh

COPY libapilog.so /app/libapilog.so

COPY malicious_check.py /app/malicious_check.py

RUN chmod +x /app/runner.sh

ENTRYPOINT ["/app/runner.sh"]
