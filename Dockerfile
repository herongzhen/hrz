FROM ubuntu:16.04

RUN apt update
RUN apt-get install build-essential git bison flex libxml2-dev libpcap-dev libtool libtool-bin rrdtool librrd-dev autoconf pkg-config automake autogen redis-server wget libsqlite3-dev libhiredis-dev libmaxminddb-dev libcurl4-openssl-dev libpango1.0-dev libcairo2-dev libnetfilter-queue-dev zlib1g-dev libssl-dev libcap-dev libnetfilter-co
nntrack-dev -y
 
RUN apt install libcurl4-openssl-dev -y
RUN apt install libsqlite3-dev -y
RUN apt install libmysqlclient-dev -y

RUN apt-get install libtool-bin -y

RUN git clone https://github.com/ntop/ntopng.git
RUN cd ntopng
RUN git clone https://github.com/ntop/nDPI.git
RUN cd nDPI;sh ./autogen.sh; ./configure; make;cd ..

WORKDIR /ntopng

RUN cd /ntopng;sh ./autogen.sh; ./configure
RUN make;make install
 
COPY startup.sh /bin/
RUN chmod +x /bin/startup.sh
RUN apt-get install tcpreplay -y
ENTRYPOINT ["/bin/startup.sh"]
