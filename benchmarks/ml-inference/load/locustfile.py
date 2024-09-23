import json
import os
import logging
from random import randint, choice
import pandas as pd

from locust import HttpUser, constant, task, LoadTestShape, events

# logging
logging.getLogger().setLevel(logging.INFO)

dataset = pd.read_csv("./twitter_training.csv", header=None)
print(dataset.iloc[:, :].sample(n=1).values[0][3])

class UserBehavior(HttpUser):

    wait_time = constant(0.3)

    @task
    def load(self) -> None:
        """
        Simulates user behaviour.
        :return: None
        """
        query = dataset.iloc[:, :].sample(n=1).values[0][3]
        res = self.client.get(f"/?query={query}")

DATAPATH = os.getenv("DATAPATH") if os.getenv("DATAPATH") != None else "."

file_raw_requests = open(f"{DATAPATH}/raw_requests.csv", "w")
file_raw_users = open(f"{DATAPATH}/raw_users.csv", "w")

@events.request.add_listener
def on_request(*args, **kwargs):
    file_raw_requests.write(f'{int(kwargs["start_time"]*1_000)},{int(kwargs["start_time"]*1_000) + int(kwargs["response_time"])},{int(kwargs["response_time"])}\n')

# @events.worker_report.add_listener
# def on_worker_report(*args, **kwargs):
#     import pdb; pdb.set_trace()

import time
from locust import runners

@events.spawning_complete.add_listener
def on_spawning_complete(user_count):
    file_raw_users.write(f'{time.time()},{user_count}\n')

@events.quit.add_listener
def on_quit(*args, **kwargs):
    file_raw_requests.close()
    file_raw_users.close()
