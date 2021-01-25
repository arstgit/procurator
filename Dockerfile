FROM gcc
COPY . /app
WORKDIR /app
RUN make && make install
