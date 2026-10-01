# Intentionally insecure Dockerfile used to demo the reviewer.
FROM python:latest
MAINTAINER dev@example.com

ENV DB_PASSWORD=SuperSecret123
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

WORKDIR app
ADD . /app
ADD https://example.com/install.sh /tmp/install.sh

RUN apt-get update
RUN apt-get install -y curl git sudo
RUN curl -fsSL https://example.com/setup.sh | bash
RUN sudo chmod -R 777 /app
RUN pip install -r requirements.txt

EXPOSE 22 8000
CMD python app.py
