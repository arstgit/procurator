FROM derekchuank/rdp
COPY . /app
WORKDIR /app
RUN make && make install
EXPOSE 444/tcp
EXPOSE 444/udp
