# Build DPDK Docker image

To build a docker image run the following command from dpdk root directory.

```
DOCKER_TAG="dpdk"
docker build -t ${DOCKER_TAG} -f extras/Dockerfile.ubuntu .
```
