FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y wget libcurl4

# Install SGX ubuntu repository
RUN echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu mantic main' | tee /etc/apt/sources.list.d/intel-sgx-mantic.list && \
    echo 'Package: *' | tee  /etc/apt/preferences.d/intel-sgx-mantic-pin-4000 && \
    echo 'Pin: release o=Intel\ Corporation,n=mantic,c=main' && \
    echo 'Pin-Priority: 499' && \
    wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    mkdir -p /etc/apt/keyrings && \
    cat intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null && \
    apt-get update

# Install QGS
RUN apt-get install -y --no-install-recommends tdx-qgs libsgx-dcap-default-qpl

# Create directory for vsock
RUN mkdir -p /var/run/tdx-qgs/

# Configure QGS
RUN sed -i "s/localhost:8081/tdx-pccs:8081/" /etc/sgx_default_qcnl.conf && \
    sed -i 's/"use_secure_cert": true/"use_secure_cert": false/' /etc/sgx_default_qcnl.conf && \
    sed -i "s/port = 4050//" /etc/qgs.conf

# Run QGS
WORKDIR /opt/intel/tdx-qgs
CMD ./qgs --no-daemon
