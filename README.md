# Build image
`docker build -t sammxendev .`

# Develop container run
`docker run --name sammxendev --env-file vars.env -v $(pwd):/app -idt sammxendev`

# Develop
`docker exec -it sammxendev /bin/bash`