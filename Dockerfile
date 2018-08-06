# check we're compatible with kong
FROM kong:0.14.0-alpine

# build dependencies
RUN apk add --no-cache \
    luarocks \
    libressl \
    git \
    libressl-dev \
    build-base \
    lua
# test dependencies
RUN luarocks install luaunit && \
    luarocks install luacov

# copy project files
COPY ./ ./
RUN luarocks make *.rockspec

# run tests
RUN chmod a+x ./ci/*
run sh ./ci/run.sh

