FROM gcc
COPY . /app
WORKDIR /app
RUN make REMOTE_HOST='"\"127.0.0.1\""' REMOTE_PORT='"\"444\""' LOCAL_PORT='"\"8080\""' && make install
EXPOSE 444
