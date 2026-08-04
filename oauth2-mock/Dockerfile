FROM python:3.14.6-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
COPY server.py .
EXPOSE 8080
CMD ["python", "-I", "-u", "server.py"]
