FROM python:3.10

WORKDIR /usr/src/app

RUN pip install locust==2.29.1
RUN pip install pandas==2.2.2

ENV DATAPATH="/usr/src/data"

COPY ./*.py ./

# ENTRYPOINT ["locust", "-f", "locustfile.py,double_wave.py", "--processes", "3"]
ENTRYPOINT ["locust", "-f", "locustfile.py,double_wave.py", "--processes", "3"]
