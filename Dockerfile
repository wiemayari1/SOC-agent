# Image facultative (NON testée dans l'environnement de livraison : à valider sur votre machine).
FROM python:3.12-slim
WORKDIR /app
COPY . .
EXPOSE 8000
# ATTENTION : --host 0.0.0.0 expose l'interface sans authentification. À réserver à un réseau de laboratoire isolé.
CMD ["python", "-m", "soc.main", "serve", "--demo", "--host", "0.0.0.0", "--no-browser"]
