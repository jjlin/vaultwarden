# The default Debian-based images support these arches for all database backends.
# Alpine-based images currently support only a subset of these.
arches=(
    amd64
    arm32v6
    arm32v7
    arm64v8
)

if [[ "${DOCKER_TAG}" == *alpine ]]; then
    os_suffix=.alpine
    arches=(
        amd64
        arm32v7
    )
fi
