# An unprivileged, offline-only demonstration image.
# No NFQUEUE support or host firewall privileges are included.
FROM python:3.12-slim
WORKDIR /app
COPY gandalf.py firewallrules.json ./
USER 65532:65532
ENTRYPOINT ["python", "gandalf.py"]
CMD ["--check-config"]