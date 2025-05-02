import os
import psycopg
from transactionmac import Transactionmac  # make sure this matches the file/module name

conn_string = os.getenv("DATABASE_URL")

args = {
    "duration": 1,
    "customers": 256,
    "days": 10,
    "update_freq": 10,
    "batch_size": 128,
    "generator_location": os.path.abspath("./Sparkov_Data_Generation"),
    "data_folder": os.path.abspath("./data/generated"),
    "master_pub_key": os.path.abspath("./secrets/master_key.pub")
}

loader = Transactionmac(args)

with psycopg.connect(conn_string) as conn:
    loader.setup(conn, id=0, total_thread_count=1)

    for step in loader.loop():
        step(conn)
