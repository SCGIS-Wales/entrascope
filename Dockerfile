# Multi stage build. The wheel is built once and installed into a clean runtime
# image, so no build tooling reaches production.

FROM python:3.14-slim AS build

WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY config ./config
RUN python -m build --wheel --outdir /dist

FROM python:3.14-slim AS runtime

# A non root user with no home directory to write into.
RUN useradd --system --no-create-home --uid 10001 entrascope

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Bind inside the container and expose only through a reverse proxy that
# terminates TLS. The canonical URI must be https and is supplied at run time.
ENV ENTRASCOPE_TENANT_ID="" \
    ENTRASCOPE_CLIENT_ID="" \
    ENTRASCOPE_BASE_URL="" \
    PYTHONUNBUFFERED=1

USER entrascope
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status == 200 else 1)"

ENTRYPOINT ["python", "-m", "entrascope"]
CMD ["serve", "http"]
