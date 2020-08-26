FROM gcc
RUN apt-get update && apt-get install sudo -y
RUN git clone https://github.com/derekchuank/rdp /rdp && cd /rdp && make BUILD=debug && make install
COPY . /app
WORKDIR /app
RUN make && make install
EXPOSE 444/tcp
EXPOSE 444/udp
