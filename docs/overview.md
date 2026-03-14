# Project Overview

This repository contains the custom Greenleaf employee activity monitoring platform.

## Scope

- `ActivityWatch` runs on each Windows PC as the local activity collector.
- This repository stores the custom server-side platform and related deployment files.
- A separate Windows sync agent will read local ActivityWatch data and send normalized events to this server.

## Current contents

- `app/` - FastAPI backend and dashboard
- `docker-compose.yml` - Docker Compose stack for the server MVP
- `Dockerfile` - app image definition
- `.env.example` - environment variables template
- `docs/` - project documentation

## Deployment target

- Domain: `tt.greenleafpacific.com`
- Runtime: Docker Compose
- Reverse proxy: existing Caddy instance on the company server
