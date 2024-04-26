# Use the latest Ubuntu LTS version as the base image
FROM ubuntu:latest

# Avoid prompts from apt during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Ubuntu desktop, VNC server, and other necessary packages
RUN apt-get update && apt-get install -y \
    dbus-x11 \
    xfce4 \
    xfce4-goodies \
    openbox \
    x11vnc \
    xvfb \
    wget \
    sudo \
    net-tools \
    locales \
    fonts-liberation \
    libu2f-udev \
    git \
    python3 \
    python3-pip \
    python3-tk \
    python3-numpy \
    python3-websockify \
    python3-flask \
    python3-watchdog \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone noVNC from its repository
RUN git clone https://github.com/novnc/noVNC.git /noVNC \
    && git clone https://github.com/novnc/websockify /noVNC/utils/websockify \
    && ln -s /noVNC/vnc.html /noVNC/index.html


# Install Google Chrome
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && apt install ./google-chrome-stable_current_amd64.deb -y \
    && rm google-chrome-stable_current_amd64.deb

# Create a user for the VNC environment
RUN useradd -ms /bin/bash user \
    && echo "user:user" | chpasswd \
    && adduser user sudo

# Set up VNC password
RUN mkdir /home/user/.x11vnc \
    && x11vnc -storepasswd user /home/user/.x11vnc/passwd

# Copy the VNC startup script
COPY start-vnc.sh /usr/local/bin/start-vnc.sh
RUN chmod +x /usr/local/bin/start-vnc.sh

COPY openbox-autostart /etc/xdg/openbox/autostart
RUN chmod +x /etc/xdg/openbox/autostart

COPY rc.xml /etc/xdg/openbox/rc.xml

COPY file-analyzer-test.py /usr/bin/test.py

#RUN pip3 install flask watchdog 

COPY downloads.py /usr/bin/download_server.py

RUN export DISPLAY=:1.0 
RUN display=:1.0

# Set default user to 'user'
USER user
WORKDIR /home/user

# Expose VNC and noVNC ports
EXPOSE 5900
EXPOSE 6080
EXPOSE 9000

# Start VNC
CMD ["/usr/local/bin/start-vnc.sh"]
