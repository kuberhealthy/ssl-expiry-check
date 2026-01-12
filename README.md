# ssl-expiry-check

The `ssl-expiry-check` verifies a TLS certificate is valid and does not expire within a configured number of days.

## Configuration

Set these environment variables in the `HealthCheck` spec:

- `DOMAIN_NAME` (required): domain name to check.
- `PORT` (required): TLS port to check (for example, `443`).
- `DAYS` (required): number of days before expiration to warn (for example, `60`).
- `INSECURE` (required): set to `true` for self-signed certificates to skip TLS verification.

## Build

- `just build` builds the container image locally.
- `just test` runs unit tests.
- `just binary` builds the binary in `bin/`.

## Example HealthCheck

Apply the example below or the provided `healthcheck.yaml`:

```yaml
apiVersion: kuberhealthy.github.io/v2
kind: HealthCheck
metadata:
  name: ssl-expiry
  namespace: kuberhealthy
spec:
  runInterval: 24h
  timeout: 15m
  podSpec:
    spec:
      containers:
        - name: ssl-expiry
          image: kuberhealthy/ssl-expiry-check:sha-<short-sha>
          imagePullPolicy: IfNotPresent
          env:
            - name: DOMAIN_NAME
              value: "example.com"
            - name: PORT
              value: "443"
            - name: DAYS
              value: "60"
            - name: INSECURE
              value: "false"
      restartPolicy: Never
```
