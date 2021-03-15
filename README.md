# Netsoc IAM

<a title="Test Cases" href="https://netsoc.testspace.com/spaces/135120">
    <img alt="Test cases badge" src="https://img.shields.io/testspace/tests/netsoc/netsoc:iam/master" />
</a>

<a title="Code Coverage (lines)" href="https://netsoc.testspace.com/spaces/135120/current/Code%20Coverage">
    <img alt="Coverage badge" src="https://netsoc.testspace.com/spaces/135120/metrics/111192/badge?token=2ed759d4f2e38ffe97c5b13095b646b8e7a35bd1" />
</a>

This project provides a microservice with a REST API, `iamd`, to manage and
authorize users. Backed by a PostgreSQL database.

An OpenAPI spec for the API can be found at
[`static/api.yaml`](static/api.yaml).

## Development

Run `docker-compose up` to build and run the test environment.
