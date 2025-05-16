# Fixed ubuntu 24.04
FROM ubuntu@sha256:1e622c5f073b4f6bfad6632f2616c7f59ef256e96fe78bf6a595d1dc4376ac02

ARG DEBIAN_FRONTEND=noninteractive \
    GO_VERSION=1.24.1 \
    GOPATH=/go \
    PATH="/usr/local/go/bin:$GOPATH/bin:$PATH"

# Install dependencies
RUN apt-get update && apt-get install -y wget lsb-release moreutils golang-cfssl \
	build-essential sqlite3 zlib1g-dev libssl-dev jq yq git curl ca-certificates \
	python3-venv libjson-glib-dev libjson-glib-1.0-0 nasm acpica-tools uuid-dev \
	genisoimage gnutls-bin guestfs-tools guestmount libtasn1-dev libgnutls28-dev \
	socat libseccomp-dev python-is-python3 libtool expect clang llvm lld

# Required for QEMU
RUN apt-get install -y git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev \
    ninja-build libnfs-dev libiscsi-dev flex git-email libaio-dev libbluetooth-dev \
	libcapstone-dev libbrlapi-dev libbz2-dev libcap-ng-dev libcurl4-gnutls-dev \
	libgtk-3-dev libibverbs-dev libjpeg8-dev libncurses5-dev libnuma-dev librbd-dev \
	librdmacm-dev libsasl2-dev libsdl2-dev libseccomp-dev libsnappy-dev libssh-dev \
	libvde-dev libvdeplug-dev libvte-2.91-dev libxen-dev liblzo2-dev valgrind \
	bison xfslibs-dev

# Install Go
RUN curl -fsSL "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz" -o go.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz

# Install SGX dependencies and EGo framework
RUN mkdir -p /etc/apt/keyrings && \
    wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null && \
    echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    EGO_DEB=ego_1.7.0_amd64_ubuntu-$(lsb_release -rs).deb && \
    wget https://github.com/edgelesssys/ego/releases/download/v1.7.0/$EGO_DEB && \
    apt-get install -y ./$EGO_DEB build-essential libssl-dev && \
    apt-get install -y libsgx-dcap-default-qpl

# Install measured-boot-tools
RUN git clone https://github.com/Fraunhofer-AISEC/measured-boot-tools.git && \
    cd measured-boot-tools && \
    make && \
    make install

# Download Intel SGX/TDX API services Sectigo public trusted CA to /etc/ssl/certs
RUN wget -q \
    http://crt.sectigo.com/SectigoRSAOrganizationValidationSecureServerCA.crt \
    -O /etc/ssl/certs/SectigoRSAOrganizationValidationSecureServerCA.crt && \
    update-ca-certificates

# Configure QGS
RUN sed -i "s/localhost:8081/tdx-pccs:8081/" /etc/sgx_default_qcnl.conf && \
    sed -i 's/"use_secure_cert": true/"use_secure_cert": false/' /etc/sgx_default_qcnl.conf

WORKDIR "/"
