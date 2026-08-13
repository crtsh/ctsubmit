# ctsubmit: REST API Documentation

Contents:

- [OpenAPI](#openapi)
- [POST Endpoints](#post-endpoints)
  - [Request Body](#request-body)
  - [Response Configuration](#response-configuration)
  - [Response Format](#response-format)
  - [Example Request](#example-request)
  - [Success Response (HTTP 200)](#success-response-http-200)
  - [Error Response (HTTP 400)](#error-response-http-400)
  - [Timeout Response (HTTP 503)](#timeout-response-http-503)
- [Security Considerations](#security-considerations)
- [Policy-Compliant Submissions](#policy-compliant-submissions)
- [GET Endpoints](#get-endpoints)
  - [Web Forms](#web-forms)
  - [Log Lists](#log-lists)
  - [Dashboard](#dashboard)
- [CTLint Severity Levels](#ctlint-severity-levels)

## OpenAPI

An [OpenAPI](https://swagger.io/specification/) definition for ctsubmit is provided by [openapi.yaml](/docs/openapi.yaml) and rendered in HTML [here](https://crtsh.github.io/ctsubmit/openapi.html).

## POST Endpoints

These endpoints accept a JSON request body containing a certificate chain and (extending the RFC6962 APIs) submission options. They return SCTs collected from CT logs.

| Endpoint | Description |
|---|---|
| `/add-chain` | Submit an X.509 certificate to CT logs. |
| `/add-pre-chain` | Submit a precertificate to CT logs. |

### Request Body

The request body is a JSON object with the following properties:

| Name | Required? | Default | Description |
|---|---|---|---|
| `chain` | Required | — | An array of base64-encoded DER certificates. The first element is the end-entity certificate; subsequent elements chain to the previous and so on to the root or a certificate that chains to a known root certificate. |
| `discoverChain` | Optional | `false` | If true, attempt to discover and append missing intermediate CA certificates to the submitted chain. Uses precomputed optimal parent data (derived from CCADB) to extend the chain from the last submitted certificate up to (but not including) a trusted root. This is useful when submitting a leaf certificate without knowing which intermediates to include. |
| `policyCompliant` | Optional | `true` | If true, ensure the resulting SCT list meets the requirements of the applicable CT policies. |
| `testLogs` | Optional | `false` | If true, submit to test CT logs instead of production CT logs. |
| `mimics` | Optional | `false` | If true, also generate SCTs from the [log mimics](https://googlechrome.github.io/CertificateTransparency/3p_libraries.html). |
| `operators` | Optional | `1` | The minimum number of distinct log operators from which to obtain SCTs. Overridden if `policyCompliant` is true and the applicable CT policies require more. |
| `scts` | Optional | `1` | The minimum number of SCTs to obtain. Overridden if `policyCompliant` is true and the applicable CT policies require more. |
| `requireAtLeastOneRFC6962SCT` | Optional | `false` | If true, require at least one SCT from an RFC 6962 log. Automatically set to true when `policyCompliant` is true (Apple CT policy). |
| `preferAtLeastOneStaticSCT` | Optional | `false` | If true, prefer at least one SCT from a Static CT API log. Automatically set to true when `policyCompliant` is true (Mozilla preference). |
| `verbose` | Optional | `false` | If true, include the submission strategy details in the response. |

### Response Configuration

The following `response.*` configuration options control which fields are included in successful responses:

| Option | Default | Description |
|---|---|---|
| `response.includeLogResponses` | `true` | Include the `logResponse` array (raw add-chain/add-pre-chain responses). |
| `response.includeSCTList` | `false` | Include the `sctListB64` field (pre-marshaled TLS-encoded SCT list, `add-pre-chain` only). |
| `response.produceFinalTBSCert` | `false` | Include the `finalTBSCertB64` and `ctlint` fields (`add-pre-chain` only). |

Review the [Security Considerations](#security-considerations) before enabling `response.includeSCTList` and/or `response.produceFinalTBSCert`.

### Response Format

The response format can be selected using the `format` query parameter or the `Accept` header:

| Format | Query parameter | Content-Type |
|---|---|---|
| JSON (default) | `?format=json` | `application/json` |
| HTML | `?format=html` | `text/html` |

### Example Request

```bash
curl -X POST https://ctsubm.it/add-chain \
  -H "Content-Type: application/json" \
  -d '{
    "chain": [
      "<base64-encoded leaf certificate>",
      "<base64-encoded intermediate certificate>"
    ],
    "policyCompliant": true
  }'
```

### Success Response (HTTP 200)

A successful response contains the collected SCTs and, for precertificate submissions, may also contain additional fields:

```json
{
  "logResponse": [
    {
      "sct_version": 0,
      "id": "<base64-encoded log ID>",
      "timestamp": 1234567890123,
      "extensions": "",
      "signature": "<base64-encoded signature>"
    }
  ],
  "sctListB64": "<base64-encoded TLS-encoded SCT list>",
  "finalTBSCertB64": "<base64-encoded TBSCertificate>",
  "ctlint": [
    {
      "finding": "Description of the finding",
      "severity": "warning"
    }
  ],
  "strategy": [...]
}
```

| Field | Presence | Description |
|---|---|---|
| `logResponse` | When `response.includeLogResponses` config is enabled (default: `true`) | Array of SCT responses from CT logs. |
| `sctListB64` | `add-pre-chain` only, when `response.includeSCTList` config is enabled (default: `false`) | Base64-encoded TLS-encoded SCT list. Use this to construct the SCT list X.509 extension and embed it in your own TBSCertificate. |
| `finalTBSCertB64` | `add-pre-chain` only, when `response.produceFinalTBSCert` config is enabled (default: `false`) | Base64-encoded TBSCertificate with the collected SCTs embedded as an SCT list extension and the CT poison extension removed. **WARNING:** Signing this value blindly means trusting ctsubmit with your CA's signing key output. See [Security Considerations](#security-considerations). |
| `ctlint` | `add-pre-chain` only, when `response.produceFinalTBSCert` config is enabled (default: `false`) | Array of [ctlint](https://github.com/crtsh/ctlint) findings for CT policy compliance checking. When `testLogs` is true, findings that only arise because the SCTs come from test logs are suppressed (see [Interaction with `testLogs`](#interaction-with-testlogs)). |
| `strategy` | When `verbose=true` | Array of strategy members showing which logs were considered, their priority buckets, and submission outcomes. |

### Error Response (HTTP 400)

Error responses use [RFC 7807 Problem Details](https://www.rfc-editor.org/rfc/rfc7807):

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "detail": "Description of the error"
}
```

### Timeout Response (HTTP 503)

If the request times out (exceeds `server.requestTimeout`), a `503 Service Unavailable` response is returned.

## Security Considerations

### Optional Response Fields

By default (`response.includeLogResponses` configuration option enabled), ctsubmit returns only the individual log responses (`logResponse`). Since there have been a number of [CA incidents](https://github.com/crtsh/ctlint#why-you-need-ctlint) in the past due to mistakes made when processing log responses, ctsubmit provides two further configuration options to assist CAs:

- The `response.includeSCTList` configuration option (default: `false`) enables the `sctListB64` response field.

- The `response.produceFinalTBSCert` configuration option (default: `false`) enables the `finalTBSCertB64` and `ctlint` response fields.

> [!CAUTION]
> It is RECOMMENDED that the CA verifies whichever of these response fields it intends to use, so that a compromise of the ctsubmit service cannot lead to the signing of arbitrary data.

For ctsubmit to remain outside a CA's trusted computing base, even if the CA is running its own instance of ctsubmit:

- The CA needs to independently verify each SCT signature using the public key of the corresponding log.

- (`add-pre-chain` only) The CA needs to independently construct the marshaled SCT list/extension and final TBSCertificate.

As long as the SCTs are kept in the same order as in `logResponse` and the SCT list extension is the last extension in the final TBSCertificate constructed by the CA, the CA can check its independent constructions by comparing against `sctListB64` and `finalTBSCertB64` and requiring a byte-for-byte match.

### CORS Policy

Responses include the header `Access-Control-Allow-Origin: *`. This is an intentional design choice: ctsubmit is a public Certificate Transparency submission proxy, and permissive CORS allows browser-based tools and web applications to submit certificates directly without requiring a server-side relay.

## Policy-Compliant Submissions

When `policyCompliant` is `true` (the default), ctsubmit automatically enforces the SCT requirements from the applicable CT policies:

| Requirement | Value |
|---|---|
| Minimum SCTs | 2 (or 3 if certificate validity > 180 days) |
| Minimum distinct operators | 2 |
| Require at least one RFC 6962 SCT | Yes (Apple CT policy) |
| Prefer at least one Static CT SCT | Yes (Mozilla preference) |

For BIMI Mark Certificates, the Usable BIMI log list is used instead of the Usable TLS log list.

### Interaction with `testLogs`

When both `policyCompliant` and `testLogs` are true, the quorum requirements above (SCT count, operator diversity, RFC 6962 requirement) are still enforced, but the following policy-compliance filters are relaxed:

- **Expired certificates are accepted** — the expiry check is skipped, allowing test submissions of expired certificates.
- **Log state is not enforced** — logs do not need to be in the `Usable` state; `ReadOnly`, `Retired`, and other states are permitted.
- **Production-log `ctlint` findings are suppressed** — whenever `testLogs` is true (independent of `policyCompliant`), the `ctlint` response field drops findings that only occur because the SCTs come from test logs absent from ctlint's bundled production log lists (e.g. "no SCTs from currently approved logs", "SCT is from an unknown log", temporal-shard mismatches). Structural, per-SCT, extension, and `notBefore` checks are still reported.

This allows testing policy-compliant submission flows against test logs that may not carry production state metadata.

## GET Endpoints

### Web Forms

Browse (i.e., send a GET request) to the `add-chain` or `add-pre-chain` endpoint to access an interactive submission form where you can paste a PEM-encoded certificate chain and configure submission options.

### Log Lists

| Endpoint | Description |
|---|---|
| `/usable_tls_logs.json` | Usable TLS CT logs — the intersection of logs marked as usable by Chrome, Apple, and Mozilla. Used for policy-compliant TLS submissions. |
| `/active_tls_logs.json` | Active TLS CT logs — all non-test logs from the crt.sh active log list. Used for non-policy-compliant submissions. |
| `/test_tls_logs.json` | Test CT logs — test-flagged logs from the crt.sh active log list. Used when `testLogs` is true. |
| `/usable_bimi_logs.json` | Usable BIMI CT logs — BIMI-approved logs from the crt.sh approved log list. Used for BIMI Mark Certificate submissions. |

### Dashboard

| Endpoint | Description |
|---|---|
| `/dashboard` | Submission dashboard showing per-log monitoring data. |

The dashboard accepts an optional `loglist` query parameter:

| Value | Description |
|---|---|
| `usabletls` (default) | Usable TLS logs |
| `activetls` | Active TLS logs |
| `testtls` | Test logs |
| `usablebimi` | Usable BIMI logs |

The dashboard displays the following information for each log:

- **STH status** — tree size, Maximum Merge Delay, and STH age.
- **Endpoint uptime** — 24-hour and 90-day uptime percentages.
- **Recent outcomes** — submission success/failure counts in the last 30 seconds.
- **Response latency** — average response time in the last 30 seconds.
- **Backoff state** — current backoff/dispreferal status and reason.

## CTLint Severity Levels

For precertificate submissions where `response.produceFinalTBSCert` is enabled, [ctlint](https://github.com/crtsh/ctlint) findings are included in the response with the following severity levels:

| Severity | Description |
|---|---|
| `info` | Informational finding. |
| `notice` | Notable observation. |
| `warning` | Potential issue that may indicate non-compliance. |
| `error` | Non-compliance with a CT policy requirement. |
| `bug` | Likely a bug in the linter itself. |
| `fatal` | Critical error that prevents further processing. |

## Strategy Buckets

When `verbose=true`, the response includes the `strategy` field, which reveals how ctsubmit prioritized each log for this request and also the response times and outcomes for each submission attempt.

| Priority | Bucket | Meaning |
|---|---|---|
| Highest | `PREFERRED_BYCONFIG` | Log URL matches a configured preference regex. |
| | `NEUTRAL` | Default — no special signals. |
| | `DISPREFERRED_SLOWRESPONSES` | Recent slow response backoff in effect. |
| | `DISPREFERRED_RECENT4XX` | Recent HTTP 4xx backoff in effect. |
| | `DISPREFERRED_RECENT5XX` | Recent HTTP 5xx backoff in effect. |
| | `DISPREFERRED_RECENTTIMEOUT` | Recent timeout backoff in effect. |
| | `DISPREFERRED_RECENTBADRESPONSE` | Recent bad response backoff in effect. |
| | `DISPREFERRED_LOWUPTIME` | Low submission-endpoint uptime. |
| | `DISPREFERRED_MMDBLOWN` | STH age exceeds the log's Maximum Merge Delay. |
| Lowest | `EXCLUDED` | Explicitly excluded by configuration, or no STH data available. |

For a detailed explanation of the submission strategy, see [SubmissionStrategy.md](/docs/SubmissionStrategy.md).
