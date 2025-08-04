# Builds a CLI docker image for Linux on the native architecture. For example,
# if you run this on an amd64 machine, you get a linux/amd64 image.

#
# Step 1: Build the Postman Insights Agent binary.
#
FROM golang:1.20.5-buster AS build

# XXX HACK Replace with Go 1.21.0.
#
# Attempting to update the base image to one that provides 1.21.0 means having
# to update to at least Debian Bullseye. But on Bullseye, libpcap is built with
# D-Bus support, which means we'd need to pull in D-Bus too.
COPY build-scripts/replace-go.sh .
RUN chmod u+rwx replace-go.sh
RUN ./replace-go.sh

RUN sed -i -e 's/deb.debian.org/archive.debian.org/g' \
  -e 's/security.debian.org/archive.debian.org\/debian-security/g' \
  -e '/buster-updates/d' /etc/apt/sources.list

# Install all dependencies and tools.
RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /src

# Download go dependencies first so docker can cache them if nothing changed.
COPY ../go.* ./
RUN go mod download

# Copy the rest of of the source code for building.
COPY ../ ./

# Produce a statically linked binary.
RUN go build -tags osusergo,netgo -ldflags "-linkmode external -extldflags '-static'" -o /out/postman-insights-agent .

#
# Step 2: Copy the binary to an empty Alpine image to export to local machine.
#
FROM scratch AS bin

COPY --from=build /out/postman-insights-agent /postman-insights-agent
