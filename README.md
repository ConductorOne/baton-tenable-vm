![Baton Logo](./baton-logo.png)

# `baton-tenable-vm` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-tenable-vm.svg)](https://pkg.go.dev/github.com/conductorone/baton-tenable-vm) ![main ci](https://github.com/conductorone/baton-tenable-vm/actions/workflows/main.yaml/badge.svg)

`baton-tenable-vm` is a connector for built using the [Baton SDK](https://github.com/conductorone/baton-sdk).

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-tenable-vm
baton-tenable-vm
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_DOMAIN_URL=domain_url -e BATON_API_KEY=apiKey -e BATON_USERNAME=username ghcr.io/conductorone/baton-tenable-vm:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-tenable-vm/cmd/baton-tenable-vm@main

baton-tenable-vm

baton resources
```

# Data Model

`baton-tenable-vm` will pull down information about the following resources:
- Users
- Groups
- Roles

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually
building spreadsheets. We welcome contributions, and ideas, no matter how
small&mdash;our goal is to make identity and permissions sprawl less painful for
everyone. If you have questions, problems, or ideas: Please open a GitHub Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-tenable-vm` Command Line Usage

```
baton-tenable-vm

Usage:
  baton-tenable-vm [flags]
  baton-tenable-vm [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --client-id string             The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string         The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --access-key string            required: Access key part of the api key ($BATON_ACCESS_KEY)
      --secret-key string            required: Secret key part of the api key ($BATON_SECRET_KEY)
  -f, --file string                  The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                         help for baton-tenable-vm
      --log-format string            The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string             The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning                 If this connector supports provisioning, this must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --ticketing                    This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                      version for baton-tenable-vm

Use "baton-tenable-vm [command] --help" for more information about a command.
```
