FROM python:3.14.7-slim-trixie@sha256:83c1cebb322d099ac9e3a3a532ba74b0146d702838b25e4c75c02fa81ffeb910
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
COPY server.py .
EXPOSE 8080
CMD ["python", "-I", "-u", "server.py"]
