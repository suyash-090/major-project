# Builds from the repo root (see docker-compose.yml's context: .), not
# from inside flag_api/, because this service imports the shared
# breachbox package, the same models, the same submissions blueprint,
# rather than duplicating any of that code here.

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5002

CMD ["python", "-m", "flag_api.app"]
