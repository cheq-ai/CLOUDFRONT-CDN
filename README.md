# CHEQ RTI for Amazon CloudFront

Lambda@Edge integration that sends every CloudFront request to CHEQ's Real-Time Interception (RTI) API and acts
on the verdict: pass, block, redirect or show a CAPTCHA (Cloudflare Turnstile) before the request reaches your origin.

## Layout

| Path | What it is |
|---|---|
| `integrations/cloudfront/` | The Lambda@Edge functions, the SAM template with the CloudFront policies, configuration, tests and the full documentation |
| `integrations/core/` | Shared code used by the CloudFront integration (RTI client, logger, decision helpers, test fixtures) |

Start with [integrations/cloudfront/README.md](integrations/cloudfront/README.md). Upgrading from an earlier
version: [integrations/cloudfront/UPGRADE.md](integrations/cloudfront/UPGRADE.md). What changed in each version:
[integrations/cloudfront/CHANGELOG.md](integrations/cloudfront/CHANGELOG.md).

## Versions

Every release is a git tag (`v1.0.0`, `v1.1.0`, …) with a matching entry on the Releases page and in the changelog.
The version in `integrations/cloudfront/package.json` is the version you run. To move between versions:

```sh
git fetch --tags
git diff v1.0.0 v1.1.0 -- integrations/     # review what changed
git checkout v1.1.0                          # or download the release archive
```

Rolling back is checking out the previous tag and redeploying.

## Building and testing

```sh
cd integrations/cloudfront
npm ci
npm test            # type check + unit tests
sam build           # package the Lambda@Edge functions
```

Deployment steps, CloudFront settings and recommended values are in the integration README and the upgrade guide.
