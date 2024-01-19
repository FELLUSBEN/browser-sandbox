#!/bin/bash

# Start Xvfb
Xvfb :1 -screen 0 1024x768x16 &
sleep 5  # Ensure Xvfb starts

export DISPLAY=:1.0

# Start XFCE without the power manager
#xfconf-query -c xfce4-session -p /sessions/Failsafe/Client0_Command -t string -sa "xfwm4" -t string -sa "xfdesktop" -t string -sa "xfce4-panel"
#startxfce4 &
# Start XFCE
#startxfce4 &
# Wait for XFCE to start
#sleep 5
# Disable XFCE panels
#xfconf-query -c xfce4-panel -p /panels -t int -s 0 -a
# Disable desktop icons
#xfconf-query -c xfwm4 -p /desktop-icons/style -s 0
# Disable right-click on the desktop
#xfconf-query -c xfce4-desktop -p /desktop-icons/file-icons/show-desktop-menu -s false
dbus-daemon --session --fork &

openbox-session &


# Start x11vnc
x11vnc -display :1 -nopw -listen localhost -xkb -forever -shared -rfbport 5900 &



# Start noVNC
/noVNC/utils/novnc_proxy --web /noVNC --listen 6080 localhost:5900
