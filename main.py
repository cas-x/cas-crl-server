# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from flask import Flask, send_file
from datetime import datetime
from os import environ
from os import path

from asn1crypto.util import timezone
from oscrypto import asymmetric
from crlbuilder import CertificateListBuilder

import pymysql
from pymysql import cursors
import StringIO


env_get = environ.get
CAS_CRL_ENV = env_get('CAS_CRL_ENV', 'PROD')
CAS_CRL_PORT = int(env_get('CAS_CRL_PORT', 9999))
CAS_CRL_KEY = env_get('CAS_CRL_KEY')
CAS_CRL_KEY_PASSWD = env_get('CAS_CRL_KEY_PASSWD')
CAS_CRL_CRT = env_get('CAS_CRL_CRT')
CAS_CRL_URL = env_get('CAS_CRL_URL')
CAS_CRL_MYSQL_HOST = env_get('CAS_CRL_MYSQL_HOST')
CAS_CRL_MYSQL_PORT = int(env_get('CAS_CRL_MYSQL_PORT', '3306'))
CAS_CRL_MYSQL_USER = env_get('CAS_CRL_MYSQL_USER')
CAS_CRL_MYSQL_PASSWD = env_get('CAS_CRL_MYSQL_PASSWD')
CAS_CRL_MYSQL_DB = env_get('CAS_CRL_MYSQL_DB')
CAS_CRL_MYSQL_CHARSET = env_get('CAS_CRL_MYSQL_CHARSET', 'utf8mb4')

app = Flask(__name__)
KEY = ""
CRT = ""

with open(CAS_CRL_KEY, "r") as f:
    KEY = f.read()

with open(CAS_CRL_CRT, "r") as f:
    CRT = f.read()

private_key = asymmetric.load_private_key(KEY, CAS_CRL_KEY_PASSWD)
certificate = asymmetric.load_certificate(CRT)

@app.route("/crl")
def crl():
    builder = CertificateListBuilder(
        unicode(CAS_CRL_URL),
        certificate,
        1000
    )
    builder.issuer_certificate_url = None

    connection = pymysql.connect(host=CAS_CRL_MYSQL_HOST,
       port=CAS_CRL_MYSQL_PORT,
       user=CAS_CRL_MYSQL_USER,
       password=CAS_CRL_MYSQL_PASSWD,
       db=CAS_CRL_MYSQL_DB,
       charset=CAS_CRL_MYSQL_CHARSET,
       cursorclass=cursors.DictCursor)

    with connection.cursor() as cursor:
        # Read a single record
        sql = "SELECT `id`, `updated_at` FROM `pki` where is_delete=1"
        cursor.execute(sql)
        for row in cursor:
            revoked_cert_serial = row['id']
            revoked_time = row['updated_at']
            builder.add_certificate(revoked_cert_serial, revoked_time, 'key_compromise')

    certificate_list = builder.build(private_key)
    crl = certificate_list.dump()
    strIO = StringIO.StringIO()
    strIO.write(crl)
    strIO.seek(0)

    return send_file(strIO,
                     attachment_filename="cas.crl",
                     as_attachment=True)
     
if __name__ == "__main__":
    if CAS_CRL_ENV == 'DEV':
        app.run(debug=True)
    else:
        app.run(host="0.0.0.0", port=CAS_CRL_PORT, debug=True)

