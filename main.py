from flask import Flask
from datetime import datetime
from os.environ import get as env_get

from asn1crypto.util import timezone
from oscrypto import asymmetric
from crlbuilder import CertificateListBuilder

import pymysql
from pymysql import cursors


CAS_CRL_ENV = env_get('CAS_CRL_ENV', 'DEV')
CAS_CRL_KEY = env_get('CAS_CRL_KEY')
CAS_CRL_CRT = env_get('CAS_CRL_CRT')
CAS_CRL_KEY_PASSWD = env_get('CAS_CRL_KEY_PASSWD')
CAS_CRL_URL = env_get('CAS_CRL_URL')
CAS_CRL_MYSQL_USER = env_get('CAS_CRL_MYSQL_USER')
CAS_CRL_MYSQL_HOST = env_get('CAS_CRL_MYSQL_HOST')
CAS_CRL_MYSQL_PASSWD = env_get('CAS_CRL_MYSQL_PASSWD')
CAS_CRL_MYSQL_DB = env_get('CAS_CRL_MYSQL_DB')
CAS_CRL_MYSQL_CHARSET = env_get('CAS_CRL_MYSQL_CHARSET', 'utf8mb4')

app = Flask(__name__)
private_key = asymmetric.load_private_key(CAS_CRL_KEY, CAS_CRL_KEY_PASSWD)
certificate = asymmetric.load_certificate(CAS_CRL_CRT)

@app.route("/crl")
def crl():
    builder = CertificateListBuilder(
        CAS_CRL_URL
        certificate,
        1000
    )

    # Connect to the database
    try:
        connection = pymysql.connect(host=CAS_CRL_MYSQL_HOST,
           user=CAS_CRL_MYSQL_USER,
           password=CAS_CRL_MYSQL_PASSWD,
           db=CAS_CRL_MYSQL_DB,
           charset=CAS_CRL_MYSQL_CHARSET,
           cursorclass=cursors.DictCursor)

        with connection.cursor() as cursor:
            # Read a single record
            sql = "SELECT `id`, `id` FROM `pki` where is_delete=1"
            cursor.execute(sql)
            for row in cursor.fetch():
                revoked_cert_serial = row['id']
                revoked_time = row['updated_at']
                builder.add_certificate(revoked_cert_serial, revoked_time, 'key_compromise')

        certificate_list = builder.build(private_key)
        print(certificate_list.dump())

    finally:
        connection.close()


if __name__ == "__main__":
    app.run()

