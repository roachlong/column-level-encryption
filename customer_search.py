import os
import psycopg2
import PySimpleGUI as sg
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
import uuid

# ─── CONFIG ────────────────────────────────────────────────────────────────
conn_string_url = os.getenv("DATABASE_URL")
master_key_file = os.getenv("MASTER_KEY_PEM")
master_passphrase = os.getenv("MASTER_PASSPHRASE").encode("utf-8")

# ─── KEY LOADING & UNWRAP ───────────────────────────────────────────────────
def load_master_private_key(path, passphrase):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase)

def fetch_wrapped_keys():
    with psycopg2.connect(conn_string_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, wrapped_dek FROM key_registry")
            return [(row[0], bytes(row[1])) for row in cur.fetchall()]

def unwrap_deks(priv_key, wrapped_list):
    unwrapped = []
    for key_id, wrapped in wrapped_list:
        dek = priv_key.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        unwrapped.append((key_id, dek))
    return unwrapped

def build_keys_cte(unwrapped):
    """
    Returns:
    WITH keys(key_id, data_key) AS (
      VALUES
        ('uuid1'::UUID, decode('deadbeef...', 'hex')),
        ('uuid2'::UUID, decode('cafebabe...', 'hex'))
    )
    """
    lines = []
    for key_id, dek in unwrapped:
        hexstr = dek.hex()
        lines.append(f"  ('{key_id}'::UUID, decode('{hexstr}','hex'))")
    return "WITH keys(key_id, data_key) AS (\n  VALUES\n" + ",\n".join(lines) + "\n)\n"

# ─── GUI / QUERYING ─────────────────────────────────────────────────────────
def fetch_last_names():
    with psycopg2.connect(conn_string_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT last FROM customer ORDER BY last")
            return [row[0] for row in cur.fetchall()]

def query_customers(keys_cte, last_name):
    sql = f"""{keys_cte}
SELECT
  u.id,
  convert_from(decrypt_iv(u.ssn, k.data_key, u.iv, 'aes'), 'UTF8') AS ssn,
  u.cc_num, u.first, u.last,
  u.gender, u.job, u.dob, u.acct_num, u.profile
FROM customer AS u
JOIN keys AS k ON u.key_id = k.key_id
WHERE u.last = %s
ORDER BY u.first;
"""
    with psycopg2.connect(conn_string_url) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (last_name,))
            cols = [c.name for c in cur.description]
            return cols, cur.fetchall()

def main():
    # 1) prepare common table expression with data encrytion keys
    priv = load_master_private_key(master_key_file, master_passphrase)
    wrapped = fetch_wrapped_keys()
    unwrapped = unwrap_deks(priv, wrapped)
    keys_cte = build_keys_cte(unwrapped)

    # 2) fetch last names for typeahead
    last_names = fetch_last_names()

    # Initial empty data
    header = ["id","ssn","cc_num","first","last","gender","job","dob","acct_num","profile"]
    rows_data = []  # store decrypted rows for copy

    # 3) build the GUI
    sg.theme("LightBlue2")
    layout = [
        [sg.Text("Select last name:"),
         sg.Combo(last_names, key="-LAST-", size=(30,1), enable_events=True)],
        [sg.Table(
            values=rows_data,
            headings=header,
            key="-TABLE-",
            auto_size_columns=True,
            justification="left",
            num_rows=5,
            enable_events=True,         # fires '-TABLE-' on row‐select
            enable_click_events=True,   # fires a ('-TABLE-','+CLICKED+') event on any click
            select_mode=sg.TABLE_SELECT_MODE_BROWSE
        )],
        [sg.Button("Exit")]
    ]
    window = sg.Window("Customer Lookup", layout, finalize=True)

    # Bind double-click on table to copy cell
    # table_elem = window["-TABLE-"]
    # table_widget = table_elem.Widget
    # def copy_cell(event):
    #     # Identify region, row, col under click
    #     region = table_widget.identify("region", event.x, event.y)
    #     if region == "cell":
    #         row_id = table_widget.identify_row(event.y)
    #         col_id = table_widget.identify_column(event.x)
    #         if row_id and col_id:
    #             row_idx = table_widget.index(row_id)
    #             col_idx = int(col_id.replace('#','')) - 1
    #             try:
    #                 val = rows_data[row_idx][col_idx]
    #             except Exception:
    #                 return
    #             # Copy to clipboard
    #             window.TKroot.clipboard_clear()
    #             window.TKroot.clipboard_append(str(val))
    #             sg.popup_quick_message(f"Copied: {val}", auto_close=True, non_blocking=True)
    # # Use double-click (Button-1 Double) to trigger
    # table_widget.bind('<Double-1>', copy_cell, add='+')

    # 4) event loop
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Exit"):
            break

        # Handle table click events, but only when clicking a cell
        if isinstance(event, tuple) and event[0] == "-TABLE-" and event[1] == "+CLICKED+":
            coords = event[2]
            # Only proceed if coords is a valid (row, col) tuple
            if coords and isinstance(coords, tuple):
                row, col = coords
                if row is not None and col is not None:
                    try:
                        val = rows_data[row][col]
                    except Exception:
                        continue
                    # Copy to clipboard
                    window.TKroot.clipboard_clear()
                    window.TKroot.clipboard_append(str(val))
                    sg.popup_quick_message(f"Copied: {val}", auto_close=True, non_blocking=True)

        if event == "-LAST-":
            last = values["-LAST-"]
            if last:
                cols, rows = query_customers(keys_cte, last)
                # Format rows (e.g. convert date to string)
                formatted = []
                for r in rows:
                    row = list(r)
                    # if dob is datetime.date, convert to ISO
                    if isinstance(row[7], (datetime, )):
                        row[7] = row[7].isoformat()
                    formatted.append(row)
                rows_data = formatted
                window["-TABLE-"].update(formatted)

    window.close()

if __name__ == "__main__":
    main()
