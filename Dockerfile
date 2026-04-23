FROM python:3.12-slim
LABEL classification="UNCLASSIFIED//FOR PUBLIC RELEASE"
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e ../../shared && pip install --no-cache-dir -e .
ENTRYPOINT ["stigsentry"]
