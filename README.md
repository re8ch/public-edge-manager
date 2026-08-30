# Public Edge Manager

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/public-edge-manager)](https://artifacthub.io/packages/search?repo=public-edge-manager)

This chart packages the `PublicEdge` inventory, health authority and DNS answer
service as one application. It does not write Cloudflare records directly.
ExternalDNS remains the publication executor for NS/glue ownership, while this
authority answers delegated service names from live `PublicEdge` health.
For names that are not yet delegated, one elected manager patches a single
ExternalDNS-only Ingress with the healthy default-area target. Application
HTTPRoute/TLSRoute objects must not also carry ExternalDNS eligibility.

Selection is deterministic:

1. unhealthy, disabled and draining edges are excluded;
2. a healthy edge in the querying NS replica's coarse `area` (CN/US/EU/APAC)
   always beats a remote edge;
3. inside an area, `capacityMbps` is the dominant score, followed by explicit
   priority and measured application latency;
4. a `RegionalRelay` publishes its local public endpoint but forwards traffic
   to the declared origin area/Gateway VIP.

For the default CN inventory this makes R640 (1000 Mbps) the preferred A answer
for `registry.re8ch.com` and control panels once its 443/TLS/application probes
are healthy. A US authority instead selects a healthy US relay and leaves the
CN origin behind that relay.
