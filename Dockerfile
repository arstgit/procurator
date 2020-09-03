FROM gcc
COPY . /app
WORKDIR /app
RUN make BUILD=debug && make install
EXPOSE 444/tcp
EXPOSE 444/udp
