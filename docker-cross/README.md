## Prepare builder images

These are just the `rustembedded/cross:${arch}` images with native library
dependencies installed.

From the `docker-cross` dir:
```
$ docker build -t jjlin/bitwardenrs-cross:aarch64-unknown-linux-gnu -f Dockerfile.aarch64-unknown-linux-gnu .
$ docker build -t jjlin/bitwardenrs-cross:armv7-unknown-linux-gnueabihf -f Dockerfile.armv7-unknown-linux-gnueabihf .
```

## Run cross

```
docker-host$ docker run -it -e CROSS_DOCKER_IN_DOCKER=true -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/usr/src/bwrs -w /usr/src/bwrs --rm rust bash
root@c7fddc07d311:/usr/src/bwrs# wget https://download.docker.com/linux/static/stable/x86_64/docker-19.03.12.tgz
root@c7fddc07d311:/usr/src/bwrs# tar -C /usr/local/bin --strip-components=1 -xf docker-19.03.12.tgz docker/docker
root@c7fddc07d311:/usr/src/bwrs# cargo install cross
root@c7fddc07d311:/usr/src/bwrs# cross build --features sqlite --target aarch64-unknown-linux-gnu
```
