from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
from datetime import timedelta
from enum import Enum
import os
import psycopg
import random
import subprocess
import time
import uuid

class Field(Enum):
    ssn = 0
    cc_num = 1
    first = 2
    last = 3
    gender = 4
    street = 5
    city = 6
    state = 7
    zip = 8
    lat = 9
    lng = 10
    city_pop = 11
    job = 12
    dob = 13
    acct_num = 14
    profile = 15
    trans_num = 16
    trans_date = 17
    trans_time = 18
    unix_time = 19
    category = 20
    amt = 21
    is_fraud = 22
    merchant = 23
    merch_lat = 24
    merch_lng = 25
    merch_id = 26


class Transactionmac:

    def __init__(self, args: dict):
        # args is a dict of string passed with the --args flag
        # user passed a yaml/json, in python that's a dict object
        self.customers: int = int(args.get("customers", 10))
        self.days: int = int(args.get("days", 10))
        self.batch_size: int = int(args.get("batch_size", 128))
        self.update_freq: int = int(args.get("update_freq", 10))
        self.generator_location: string = str(args.get("generator_location",
            f"{os.environ['HOME']}/workspace/column-level-encryption/Sparkov_Data_Generation"))
        self.data_folder: string = str(args.get("data_folder",
            f"{os.environ['HOME']}/workspace/column-level-encryption/data/generated"))
        self.master_pub_key: string = str(args.get("master_pub_key",
            f"{os.environ['HOME']}/workspace/column-level-encryption/secrets/master_key.pub"))

        # you can arbitrarely add any variables you want
        self.counter: int = 0



    # the setup() function is executed only once
    # when a new executing thread is started.
    # Also, the function is a vector to receive the excuting threads's unique id and the total thread count
    def setup(self, conn: psycopg.Connection, id: int, total_thread_count: int):
        self.id = id

        # Generate a new AES-256 data key for customer ssn and store in registry
        self.data_key = os.urandom(32)
        with open(f"{self.master_pub_key}", "rb") as f:
            public_pem = f.read()
        public_key = serialization.load_pem_public_key(public_pem)
        wrapped_dek = public_key.encrypt(
            self.data_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with conn.cursor() as cur:
            print(
                f"My thread ID is {id}. The total count of threads is {total_thread_count}"
            )
            cur.execute("""
                INSERT INTO key_registry (wrapped_dek)
                VALUES (%s)
                RETURNING id
            """, (psycopg.Binary(wrapped_dek),))
            self.key_id = cur.fetchone()[0]
        
        # and push the transaction to CockroachDB in case autocimmit is not enabled yet
        conn.commit()



    # the run() function returns a list of functions
    # that dbworkload will execute, sequentially.
    # Once every func has been executed, run() is re-evaluated.
    # This process continues until dbworkload exits.
    def loop(self):
        command = [
            "rm",
            "-rf",
            f"{self.data_folder}/{self.id}"
        ]
        # print(f"executing command: {command}")
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        start_days_ahead = (self.days * self.counter) + 1
        start_date=datetime.datetime.now() + timedelta(days=start_days_ahead)
        end_date=start_date + timedelta(days=self.days)

        command = [
            "python3",
            "./datagen.py",
            "-n",
            str(self.customers),
            "-o",
            f"{self.data_folder}/{self.id}",
            start_date.strftime("%m-%d-%Y"),
            end_date.strftime("%m-%d-%Y")
        ]
        # print(f"executing command: {command}")
        subprocess.run(command,
                       cwd=self.generator_location,
                       input="y",             # text to send on stdin
                       text=True,             # treat input/output as text
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT,
                       check=True)

        self.records = []
        # print(f"id: {self.id} and counter: {self.counter} LOOP completed")
        return [self.parse, self.transact]



    # conn is an instance of a psycopg connection object
    # conn is set by default with autocommit=True, so no need to send a commit message
    def parse(self, conn: psycopg.Connection):
        self.counter += 1
        # print(f"id: {self.id} and counter: {self.counter} PARSE called")

        directory = f"{self.data_folder}/{self.id}"
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            base = os.path.basename(filepath)
            ext = os.path.splitext(filepath)[-1]
            if not base.startswith('customers') and ext == '.csv':
                if os.path.getsize(filepath) == 0:
                    continue
                with open(filepath, 'r') as file:
                    next(file) # skip the first line (header)
                    for line in file:
                        record = line.strip().split('|')
                        record.append(uuid.uuid5(uuid.NAMESPACE_DNS, record[Field.merchant.value]))
                        self.records.append(record)



    def execute(self, conn: psycopg.Connection, data, record_cnt, ins_sql, conflict_sql):
        fields = ','.join("%s" for i in range(int(len(data) / record_cnt)))
        values = ','.join(f"({fields})" for i in range(record_cnt))
        with conn.cursor() as cur:
            cur.execute(f"{ins_sql} VALUES {values} {conflict_sql};", tuple(data))



    def execute_customer(self, conn: psycopg.Connection, data, record_cnt, ins_sql, conflict_sql):
        fields = '%s::STRING, %s::INT8, %s::STRING, %s::STRING, %s::STRING, %s::STRING, %s::DATE, %s::INT8, %s::STRING'
        values = ','.join(f"({fields})" for i in range(record_cnt))
        main_sql = f"""
            SELECT
                encrypt_iv(
                    t.ssn::BYTES,
                    %s::BYTES,
                    ivl.iv::BYTES,
                    'aes'
                ),
                %s::UUID,
                ivl.iv::BYTES,
                t.cc_num::INT8,
                t.first::STRING,
                t.last::STRING,
                t.gender::STRING,
                t.job::STRING,
                t.dob::DATE,
                t.acct_num::INT8,
                t.profile::STRING
            FROM (VALUES {values})
            AS t(ssn, cc_num, first, last, gender, job, dob, acct_num, profile)
            CROSS JOIN LATERAL (
                SELECT gen_random_bytes(16) AS iv
            ) AS ivl
        """
        params = [self.data_key,  self.key_id]
        params.extend(data)
        with conn.cursor() as cur:
            cur.execute(f"""
                {ins_sql}
                {main_sql}
                {conflict_sql};
            """, params)



    def flush_address(self, conn: psycopg.Connection, data, record_cnt, sql):
        # print(f"id: {self.id} and counter: {self.counter} FLUSH_ADDRESS called")
        if (random.randint(1, 100) <= self.update_freq):
            resolve_it = """
            ON CONFLICT (acct_num) DO UPDATE SET
                street = excluded.street,
                zip = excluded.zip,
                lat = excluded.lat,
                lng = excluded.lng
            """
            self.execute(conn, data, record_cnt, sql, resolve_it)
        else:
            do_nothing = "ON CONFLICT DO NOTHING"
            self.execute(conn, data, record_cnt, sql, do_nothing)



    def flush_city_loc(self, conn: psycopg.Connection, data, record_cnt, sql):
        # print(f"id: {self.id} and counter: {self.counter} FLUSH_CITY_LOC called")
        if (random.randint(1, 100) <= self.update_freq):
            resolve_it = """
            ON CONFLICT (zip) DO UPDATE SET
                city = excluded.city,
                state = excluded.state,
                city_pop = excluded.city_pop
            """
            self.execute(conn, data, record_cnt, sql, resolve_it)
        else:
            do_nothing = "ON CONFLICT DO NOTHING"
            self.execute(conn, data, record_cnt, sql, do_nothing)



    def flush_customer(self, conn: psycopg.Connection, data, record_cnt, sql):
        # print(f"id: {self.id} and counter: {self.counter} FLUSH_CUSTOMER called")
        if (random.randint(1, 100) <= self.update_freq):
            resolve_it = """
            ON CONFLICT (acct_num) DO UPDATE SET
                ssn = excluded.ssn,
                key_id = excluded.key_id,
                iv = excluded.iv,
                cc_num = excluded.cc_num,
                first = excluded.first,
                last = excluded.last,
                gender = excluded.gender,
                job = excluded.job,
                dob = excluded.dob,
                profile = excluded.profile
            """
            self.execute_customer(conn, data, record_cnt, sql, resolve_it)
        else:
            do_nothing = "ON CONFLICT DO NOTHING"
            self.execute_customer(conn, data, record_cnt, sql, do_nothing)



    def flush_merchant(self, conn: psycopg.Connection, data, record_cnt, sql):
        # print(f"id: {self.id} and counter: {self.counter} FLUSH_MERCHANT called")
        if (random.randint(1, 100) <= self.update_freq):
            resolve_it = """
            ON CONFLICT (id) DO UPDATE SET
                merchant = excluded.merchant,
                merch_lat = excluded.merch_lat,
                merch_lng = excluded.merch_lng
            """
            self.execute(conn, data, record_cnt, sql, resolve_it)
        else:
            do_nothing = "ON CONFLICT DO NOTHING"
            self.execute(conn, data, record_cnt, sql, do_nothing)



    def transact(self, conn: psycopg.Connection):
        # print(f"id: {self.id} and counter: {self.counter} TRANSACT called")

        addr_sql = """
        INSERT INTO address (
            acct_num, street, zip, lat, lng
        )
        """
        addr_cnt = 0
        addr_data = []
        unique_addr = []

        city_sql = """
        INSERT INTO city_loc (
            zip, city, state, city_pop
        )
        """
        city_cnt = 0
        city_data = []
        unique_city = []

        cust_sql = """
        INSERT INTO customer (
            ssn, key_id, iv, cc_num, first, last, gender, job, dob, acct_num, profile
        )
        """
        cust_cnt = 0
        cust_data = []
        unique_cust = []

        merc_sql = """
        INSERT INTO merchant (
            id, merchant, merch_lat, merch_lng
        )
        """
        merc_cnt = 0
        merc_data = []
        unique_merc = []

        sql = """
        INSERT INTO transaction (
            cc_num, trans_num, trans_date, trans_time, unix_time, category, merch_id, amt, is_fraud
        )
        """
        record_cnt = 0
        data = []

        for record in self.records:

            # ADDRESS
            acct_num = record[Field.acct_num.value]
            if acct_num in unique_addr:
                self.flush_address(conn, addr_data, addr_cnt, addr_sql)
                addr_cnt = 0
                addr_data = []
                unique_addr = []
                
            unique_addr.append(acct_num)
            addr_cnt += 1
            addr_data += [
                acct_num,
                record[Field.street.value],
                record[Field.zip.value],
                record[Field.lat.value],
                record[Field.lng.value]
            ]

            if addr_cnt >= self.batch_size:
                self.flush_address(conn, addr_data, addr_cnt, addr_sql)
                addr_cnt = 0
                addr_data = []
                unique_addr = []


            # CITY LOCATION
            zip = record[Field.zip.value]
            if zip in unique_city:
                self.flush_city_loc(conn, city_data, city_cnt, city_sql)
                city_cnt = 0
                city_data = []
                unique_city = []

            unique_city.append(zip)
            city_cnt += 1
            city_data += [
                zip,
                record[Field.city.value],
                record[Field.state.value],
                record[Field.city_pop.value]
            ]

            if city_cnt >= self.batch_size:
                self.flush_city_loc(conn, city_data, city_cnt, city_sql)
                city_cnt = 0
                city_data = []
                unique_city = []


            # CUSTOMER
            acct_num = record[Field.acct_num.value]
            if acct_num in unique_cust:
                self.flush_customer(conn, cust_data, cust_cnt, cust_sql)
                cust_cnt = 0
                cust_data = []
                unique_cust = []

            unique_cust.append(acct_num)
            cust_cnt += 1
            cust_data += [
                record[Field.ssn.value],
                record[Field.cc_num.value],
                record[Field.first.value],
                record[Field.last.value],
                record[Field.gender.value],
                record[Field.job.value],
                record[Field.dob.value],
                acct_num,
                record[Field.profile.value]
            ]

            if cust_cnt >= self.batch_size:
                self.flush_customer(conn, cust_data, cust_cnt, cust_sql)
                cust_cnt = 0
                cust_data = []
                unique_cust = []

            # MERCHANT
            id = record[Field.merch_id.value]
            if id in unique_merc:
                self.flush_merchant(conn, merc_data, merc_cnt, merc_sql)
                merc_cnt = 0
                merc_data = []
                unique_merc = []

            unique_merc.append(id)
            merc_cnt += 1
            merc_data += [
                id,
                record[Field.merchant.value],
                record[Field.merch_lat.value],
                record[Field.merch_lng.value]
            ]

            if merc_cnt >= self.batch_size:
                self.flush_merchant(conn, merc_data, merc_cnt, merc_sql)
                merc_cnt = 0
                merc_data = []
                unique_merc = []

            # TRANSACTION
            record_cnt += 1
            data += [
                record[Field.cc_num.value],
                record[Field.trans_num.value],
                record[Field.trans_date.value],
                record[Field.trans_time.value],
                record[Field.unix_time.value],
                record[Field.category.value],
                record[Field.merch_id.value],
                record[Field.amt.value],
                record[Field.is_fraud.value]
            ]

            if record_cnt >= self.batch_size:
                self.execute(conn, data, record_cnt, sql, "")
                record_cnt = 0
                data = []


        if addr_cnt > 0:
            self.flush_address(conn, addr_data, addr_cnt, addr_sql)

        if city_cnt > 0:
            self.flush_city_loc(conn, city_data, city_cnt, city_sql)

        if cust_cnt > 0:
            self.flush_customer(conn, cust_data, cust_cnt, cust_sql)

        if merc_cnt > 0:
            self.flush_merchant(conn, merc_data, merc_cnt, merc_sql)

        if record_cnt > 0:
            self.execute(conn, data, record_cnt, sql, "")
