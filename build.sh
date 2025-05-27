#!/bin/bash
docker compose down
DOCKER_REPO=ko.local/uvensys/anubis DOCKER_METADATA_OUTPUT_TAGS=ko.local/uvensys/anubis:latest npm run container
docker compose up -d