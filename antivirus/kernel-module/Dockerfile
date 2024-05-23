# Use the official Ubuntu base image
FROM ubuntu:latest

# Install necessary packages
RUN apt-get update && apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    make \
    gcc \
    && apt-get clean

# Create a directory for the kernel module source code
RUN mkdir -p /usr/src/kernel_module

# Copy the kernel module source code to the container
COPY hook_syscall.c /usr/src/kernel_module/
COPY Makefile /usr/src/kernel_module/

# Set the working directory
WORKDIR /usr/src/kernel_module

# Build the kernel module
RUN make

# Command to keep the container running
CMD ["tail", "-f", "/dev/null"]
