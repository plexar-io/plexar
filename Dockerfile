# Trivy binary — bundled so users get CVE scanning out of the box
FROM aquasec/trivy:latest AS trivy

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
# GoReleaser places the pre-built binary in the build context
COPY plexar /usr/local/bin/plexar
USER 65534:65534
ENTRYPOINT ["plexar"]
CMD ["serve", "--bind=0.0.0.0"]
