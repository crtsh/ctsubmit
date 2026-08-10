# ctsubmit [![CI](https://github.com/crtsh/ctsubmit/actions/workflows/ci.yml/badge.svg)](https://github.com/crtsh/ctsubmit/actions/workflows/ci.yml)

A REST API and web interface for submitting (pre)certificate chains to [Certificate Transparency](https://certificate.transparency.dev/) logs and collecting Signed Certificate Timestamps (SCTs).

At a glance:

- [Features](#features)
- [Why use ctsubmit?](#why-use-ctsubmit)
- [Docker containers](#docker-containers)
- [Public instances](#public-instances)
- [About this project](#about-this-project)
- [Mascot](#mascot)

Details:

- [Installation and Configuration](docs/INSTALL.md)
- [REST API Documentation](docs/REST_API.md)
- [Submission Strategy](docs/SubmissionStrategy.md)

## Features

- Extends the [RFC 6962 §4.1/§4.2](https://www.rfc-editor.org/rfc/rfc6962.html#section-4.1) `add-chain` and `add-pre-chain` request format.
- Verifies each submitted chain and determines which log(s) will accept it.
- Intelligent submission strategy: Ranks and prioritizes logs based on uptime, responsiveness, and recent error history, with automatic backoff for misbehaving logs. Submits to multiple logs in parallel. Speculatively starts additional submissions when logs are slow to respond. Stops as soon as the required quorum of SCTs is achieved, cancelling any in-flight submissions.
- Unified CT log lists: Usable public logs (Usable in all of the applicable CT client log lists), Available public logs (both Usable and non-Usable), Test logs, and log mimics.
- (Optional) Certificate chain discovery: Automatically discovers and appends missing intermediate CA certificates using precomputed optimal parent data derived from the [CCADB](https://www.ccadb.org/). Selects the parent certificate that maximizes the number of compatible CT logs, preferring shorter chains.
- (Optional) CT policy-compliant SCT collection: Automatically determines how many SCTs of what types ([RFC6962](https://www.rfc-editor.org/rfc/rfc6962) and/or [Static CT API](https://c2sp.org/static-ct-api)) are needed/desired (and from how many distinct log operators) in order to satisfy whichever of the Chrome, Apple, Mozilla, and BIMI Group CT policies are applicable.
- For each precertificate submission:
  - Returns a TBSCertificate with the collected SCTs embedded as an SCT list extension, ready for signing.
  - Verifies that the embedded SCT list does indeed comply with the applicable CT policies, using [ctlint](https://github.com/crtsh/ctlint).
- Monitoring: Provides a built-in web UI that shows per-log STH status, uptime, recent submission outcomes, response latencies, and backoff state. Prometheus metrics. Health probes.
- Optimized for performance and scalability.
- Dockerized.

## Why use ctsubmit?

- CT policy compliance is complex: Different CT clients have different CT policies with different SCT requirements, some of them subtle. Getting this right requires tracking which logs are Usable, how many distinct operators are needed, whether any RFC6962 SCTs are required, and whether Static CT SCTs are acceptable. **ctsubmit handles all of this for you**.
- Log selection is non-trivial: Not every log accepts every certificate. Temporal compatibility, accepted root certificates, and log operational status all matter. **ctsubmit dynamically filters and selects the right logs**.
- Reliability matters: CT logs can be slow, return errors, or blow their Maximum Merge Delay. ctsubmit tracks all of these signals and automatically deprioritizes unreliable logs, using backoff periods and uptime thresholds. **ctsubmit keeps submitting even when some logs are having a bad day**.
- Performance matters: ctsubmit submits to multiple logs concurrently, races slow responses against fresh attempts, and cancels in-flight requests as soon as quorum is met. **ctsubmit minimizes the latency impact of CT on certificate issuance**.

## Docker containers

[Docker containers](https://github.com/orgs/crtsh/packages?repo_name=ctsubmit) are pre-built automatically and published on the GitHub Container Registry (GHCR).

- [Stable](https://github.com/crtsh/ctsubmit/pkgs/container/ctsubmit) releases: These have a "vX.X.X" tag on GHCR and are automatically built and published whenever a corresponding [ctsubmit release](https://github.com/crtsh/ctsubmit/releases) is created. The most recent Stable release also receives the "latest" tag. **Only Stable releases are recommended for production usage**.
- [Development](https://github.com/crtsh/ctsubmit/pkgs/container/ctsubmit-dev) releases: These have a "YYYYMMDDHHMMSS" tag on GHCR and are automatically built and published whenever a corresponding [commit](https://github.com/crtsh/ctsubmit/commits/main/) is pushed to the "main" branch. Since Development releases track the latest commits to the "main" branch, they are NOT RECOMMENDED for production usage.

## Public instances

Sectigo provides public instances of ctsubmit that correspond to the two release cycles:

- Stable: https://ctsubm.it
- Development: https://dev.ctsubm.it

These public instances are provided as-is, on a best effort basis. They are NOT RECOMMENDED for production usage by CAs, because (due to CABForum Ballot SC-75) they may be seen as Delegated Third Parties. Your own deployment of the [Docker container](#docker-containers) for the latest Stable release is the appropriate way to deploy ctsubmit in a production CA environment.

## Known users/integrations

Here are some projects/CAs that are known to use or integrate with ctsubmit:

- [ctsubm.it](https://ctsubm.it) (Sectigo): The two [Public instances](#public-instances) listed above

Please submit a pull request to update README.md if you are aware of another CA/project that uses or integrates with ctsubmit.

## About this project

ctsubmit was created and is maintained by [Rob Stradling](https://github.com/robstradling) at Sectigo. It is hoped that other publicly-trusted CAs and ecosystem participants will benefit and collaborate on future development. :-)

## Mascot

Meet [Sir Tiffy Cat](https://ctsubm.it/mascot.png), your friendly neighbourhood cartoon cer-tifi-cate. 😉

![Sir Tiffy Cat](server/images/mascot.png)

Sir Tiffy Cat is a founding member of the legendary, chivalric fellowship of The Bytes of the Wound Cable. 🤣
