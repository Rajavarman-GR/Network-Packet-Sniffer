import logging
import os


LOG_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "sniffer.log"))
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(

    filename=LOG_PATH,

    level=logging.INFO,

    format="%(asctime)s | %(levelname)s | %(message)s"

)


def log_info(message):

    logging.info(message)


def log_error(message):

    logging.error(message)


def log_warning(message):

    logging.warning(message)