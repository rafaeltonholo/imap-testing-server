FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
COPY server.py .
EXPOSE 8080
CMD ["python", "-I", "-u", "server.py"]
