# column-level-encryption
This repo provides a demonstration and general recommendation on how to use field level encryption in CRDB.  Below is a summary of the column-level encryption demo, where multiple keys are maintained in a registry and envelope encryption is used to ease key management.  We also leverage a common table expression to obfuscate key usage in application queries.

<p align="left">
<img src="https://github.com/user-attachments/assets/0b11d7f8-d111-4a16-87cf-c1ca3bb0b8f8" alt="Encryption Flow" height="450px" align="left"/>
  
**Encryption Flow (left panel)**
<ul>
  <li>Retrieve the Asymmetric Master Key from your secure vault.</li>
  <li>Generate a Data Encryption Key (DEK) in the application.</li>
  <li>Wrap (encrypt) the DEK with the Master Key and store it in the Key Registry.</li>
  <li>Generate an IV per record and encrypt data fields using encrypt_iv, storing ciphertext, iv, and key_id in the Encrypted Data Table.</li>
</ul>

**Decryption Flow (right panel)**
<ul>
  <li>Retrieve the Master Key from the vault.</li>
  <li>Fetch wrapped DEKs from the Key Registry and unwrap them to plaintext DEKs.</li>
  <li>Build a SQL CTE of (key_id, data_key) pairs in your query.</li>
  <li>Decrypt fields on the fly using decrypt_iv(data_key, iv) in the query, returning cleartext results.</li>
</ul>

<br clear="all"/>
The Master Key is never stored in‐database, while the data encryption keys can safely reside in the database protected by asymmetric master key encryption.  Each encrypted field retains its IV and a reference to the key id and metadata for robust security and auditability.
</p>


## Key Registry & Envelope Encryption

We generate AES-256 Data Encryption Keys (DEKs) in the application which can be segmented by column, record, group, time period or any combination thereof.

Each DEK is encrypted (“wrapped”) under a long-term Asymmetric Master Key (AMK) which can be stored in a secure vault (HSM/KMS).

The key_registry table holds records with metadata about each DEK along with the wrapped key value which is the RSA-encrypted DEK.

For actual data encryption, we also generate a fresh 16-byte IV per record (via gen_random_bytes(16)), then call CockroachDB’s encrypt_iv(plaintext, dek, iv, 'aes'), storing both the resulting ciphertext alongside the IV and DEK UUID reference.

Key rotation is simple: we can unwrap old DEKs under your AMK, generate new DEKs, re-wrap and insert back, or re-encrypt your data keys under a new AMK—without touching the underlying data.


## Per-record IV & Key ID Tracking

Each encrypted field carries metadata:

**iv**: the 16-byte nonce used for AES-GCM per record

**key_id**: a reference to which DEK (row in key_registry) encrypted that record

This ensures both semantic security (unique IVs) and auditable key usage (via key_id).


## Querying with a CTE to Simplify the Data Layer

Rather than hard-coding any plaintext keys in your SQL or application, or managing data / key relationships outside the database, we constructed a single CTE that inlines every unwrapped DEK and can be leveraged across queries that work with encrypted data.  Following is an example:

```
WITH keys(key_id, data_key) AS (
  VALUES
    ('uuid1'::UUID, decode('deadbeef…','hex')),
    ('uuid2'::UUID, decode('cafebabe…','hex'))
)
SELECT
  id,
  convert_from(
    decrypt_iv(encrypted_ssn, k.data_key, ssn_iv, 'aes'),
    'UTF8'
  ) AS ssn,
  …other columns…
FROM users AS u
JOIN keys AS k ON u.key_id = k.key_id
WHERE …
```

This approach “hides” all the raw DEKs inside the automatically-generated CTE, so your actual query logic only references the alias k.data_key—no explicit secrets in your SQL.

The data layer can use that CTE to provide each row the correct key for AES decryption, transparently to the rest of your application.

For more information on environment setup and the steps required to build and run the demonstration please visit our [wiki pages](https://github.com/roachlong/column-level-encryption/wiki)
