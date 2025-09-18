FROM python:3.9

RUN pip install locust

WORKDIR /app

COPY locustfile.py ./

ENTRYPOINT ["locust", "-f", "locustfile.py"]
