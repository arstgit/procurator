FROM gcc
COPY . /app
WORKDIR /app
RUN mkdir build
WORKDIR /app/build
RUN autoreconf --install ..
RUN ../configure
RUN make && make install
