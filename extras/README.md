# Build DPDK Docker image

To build a docker image run the following command from dpdk root directory.

```
DOCKER_TAG="dpdk"
docker build -t ${DOCKER_TAG} -f extras/Dockerfile.bionic .
```

# Example of how to use this dpdk library image

The following steps shows how to use the dpdk shared library container to build
and run a dpdk application without having to build dpdk library for each
application.

## Create a dpdk sample app docker file with 'dpdk' as the base image

Create a docker file to build the dpdk helloworld application. Since, we are
creating a docker file for dpdk helloworld app we need to add the dpdk source
files, thus create the following docker file in dpdk root directory.

```
cat << EOF > Dockerfile.dpdkSampleApp
FROM dpdk

ADD . /opt/dpdk

WORKDIR /opt/dpdk/examples/helloworld
RUN make && cp build/helloworld-shared /usr/local/bin/helloworld
EOF
```

## Build sample app docker image

```
DOCKERAPP_TAG="dpdk-helloworld"
docker build -t ${DOCKERAPP_TAG} -f Dockerfile.dpdkSampleApp .
```

This sample app now can be run like any other applicaiton in a docker container.

```
$ docker run --rm -it  -v /dev/hugepages:/dev/hugepages dpdk-helloworld
```

## Running the sample app
Once inside the container run helloword binary

```
$ root@11233ed2e69c # helloworld
```

