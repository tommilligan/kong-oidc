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
# dev dependencies
RUN luarocks install luaunit && \
    luarocks install luacov && \
    luarocks install lua-resty-openidc

# copy project files
COPY ./ ./

# run tests
RUN chmod a+x ./ci/*
run sh ./ci/run.sh

