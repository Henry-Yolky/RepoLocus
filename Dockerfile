FROM python:3.12-slim AS builder

WORKDIR /build
COPY --from=ghcr.io/astral-sh/uv:0.9.18 /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md LICENSE NOTICE THIRD_PARTY_NOTICES ./
COPY src ./src
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
RUN uv sync --frozen --no-dev --extra api --no-editable

FROM python:3.12-slim

RUN useradd --create-home --uid 10001 repolocus \
    && mkdir -p /workspace \
    && chown repolocus:repolocus /workspace
COPY --from=builder /build/.venv /build/.venv
ENV PATH="/build/.venv/bin:$PATH"
USER repolocus
WORKDIR /workspace
EXPOSE 8765
ENTRYPOINT ["repolocus"]
CMD ["serve", "--root", "/workspace", "--host", "127.0.0.1", "--port", "8765"]
