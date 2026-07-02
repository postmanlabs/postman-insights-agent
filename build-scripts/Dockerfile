# Builds a CLI docker image for Linux on the native architecture. For example,
# if you run this on an amd64 machine, you get a linux/amd64 image.

#
# Step 1: Build the Postman Insights Agent binary.
#
FROM golang:1.25-alpine AS build

# Alpine's libpcap does not include D-Bus support, so static linking with
# -tags osusergo,netgo works cleanly without pulling in D-Bus.
# Debian-based images (Buster, Bullseye, Bookworm) compile libpcap with
# D-Bus, which causes unresolved symbol errors when linking statically.
RUN apk add --no-cache libpcap-dev gcc musl-dev

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
