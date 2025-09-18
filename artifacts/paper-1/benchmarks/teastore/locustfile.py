import json
import logging
from random import randint, choice

from locust import HttpUser, task, LoadTestShape, events

# logging
logging.getLogger().setLevel(logging.INFO)


class UserBehavior(HttpUser):

    @task
    def load(self) -> None:
        """
        Simulates user behaviour.
        :return: None
        """
        # logging.info("Starting user.")
        self.visit_home()
        self.login()
        self.browse()
        # 50/50 chance to buy
        choice_buy = choice([True, False])
        if choice_buy:
            self.buy()
        self.visit_profile()
        self.logout()
        # logging.info("Completed user.")

    def visit_home(self) -> None:
        """
        Visits the landing page.
        :return: None
        """
        # load landing page
        res = self.client.get('/')
        if res.ok:
            # logging.info("Loaded landing page.")
            pass
        else:
            logging.error(f"Could not load landing page: {res.status_code}")

    def login(self) -> None:
        """
        User login with random userid between 1 and 90.
        :return: categories
        """
        # load login page
        res = self.client.get('/login')
        if res.ok:
            # logging.info("Loaded login page.")
            pass
        else:
            logging.error(f"Could not load login page: {res.status_code}")
            print(res.text)
        # login random user
        user = randint(1, 99)
        login_request = self.client.post("/loginAction", params={"username": user, "password": "password"})
        if login_request.ok:
            # logging.info(f"Login with username: {user}")
            pass
        else:
            logging.error(
                f"Could not login with username: {user} - status: {login_request.status_code}")

    def browse(self) -> None:
        """
        Simulates random browsing behaviour.
        :return: None
        """
        # execute browsing action randomly up to 5 times
        for i in range(1, randint(2, 5)):
            # browses random category and page
            category_id = randint(2, 6)
            page = randint(1, 5)
            category_request = self.client.get("/category", params={"page": page, "category": category_id})
            if category_request.ok:
                # logging.info(f"Visited category {category_id} on page 1")
                # browses random product
                product_id = randint(7, 506)
                product_request = self.client.get("/product", params={"id": product_id})
                if product_request.ok:
                    # logging.info(f"Visited product with id {product_id}.")
                    cart_request = self.client.post("/cartAction", params={"addToCart": "", "productid": product_id})
                    if cart_request.ok:
                        # logging.info(f"Added product {product_id} to cart.")
                        pass
                    else:
                        logging.error(
                            f"Could not put product {product_id} in cart - status {cart_request.status_code}")
                else:
                    logging.error(
                        f"Could not visit product {product_id} - status {product_request.status_code}")
            else:
                logging.error(
                    f"Could not visit category {category_id} on page 1 - status {category_request.status_code}")

    def buy(self) -> None:
        """
        Simulates to buy products in the cart with sample user data.
        :return: None
        """
        # sample user data
        user_data = {
            "firstname": "User",
            "lastname": "User",
            "adress1": "Road",
            "adress2": "City",
            "cardtype": "volvo",
            "cardnumber": "314159265359",
            "expirydate": "12/2050",
            "confirm": "Confirm"
        }
        buy_request = self.client.post("/cartAction", params=user_data)
        if buy_request.ok:
            # logging.info(f"Bought products.")
            pass
        else:
            logging.error("Could not buy products.")

    def visit_profile(self) -> None:
        """
        Visits user profile.
        :return: None
        """
        profile_request = self.client.get("/profile")
        if profile_request.ok:
            # logging.info("Visited profile page.")
            pass
        else:
            logging.error("Could not visit profile page.")

    def logout(self) -> None:
        """
        User logout.
        :return: None
        """
        logout_request = self.client.post("/loginAction", params={"logout": ""})
        if logout_request.ok:
            # logging.info("Successful logout.")
            pass
        else:
            logging.error(f"Could not log out - status: {logout_request.status_code}")


file_raw_requests = open("raw_requests.csv", "w")
file_raw_users = open("raw_users.csv", "w")

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
