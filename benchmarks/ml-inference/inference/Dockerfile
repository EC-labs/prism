FROM python:3.8

WORKDIR /usr/src/app

RUN pip install pysentimiento
RUN pip install fastapi
RUN pip install uvicorn[standard]
RUN pip install gunicorn

COPY ./*.py ./

ENTRYPOINT ["gunicorn", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "api:app"]
