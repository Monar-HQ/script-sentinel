FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /build
COPY . /build
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock && python -m pip install --no-cache-dir --no-deps . && useradd --uid 10001 --create-home sentinel
USER 10001
WORKDIR /workspace
ENTRYPOINT ["scriptsentinel"]
CMD ["demo"]
