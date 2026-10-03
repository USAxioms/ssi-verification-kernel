# Reference environment for the SSI Verification Kernel capsule.
# Requires: gcc (C11, __int128), binutils (objdump), python3 (checks), Node.js >= 22.6 (TypeScript cross-check).
# node:22-bookworm is built on buildpack-deps and already includes gcc, binutils, and python3.
FROM node:22-bookworm
WORKDIR /capsule
COPY code /capsule/code
COPY data /data
RUN mkdir -p /results
CMD ["bash", "/capsule/code/run"]
