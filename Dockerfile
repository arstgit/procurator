FROM gcc
COPY . /app
WORKDIR /app
RUN make && make install
EXPOSE 444
