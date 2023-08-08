from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import os

import base64
import platform

# from eidreader import eid2dict
from PyKCS11 import PyKCS11, CKA_CLASS, CKO_DATA, CKA_LABEL, CKA_VALUE, CKO_CERTIFICATE, PyKCS11Error

app = FastAPI()

# Add middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Origin", "Accept", "Content-Type", "X-Requested-With", "X-CSRF-Token"],
)

#
# Categorize all fields to be decoded respectively to their charset
# More information: https://github.com/Fedict/eid-mw/blob/master/doc/sdk/documentation/Applet%201.8%20eID%20Cards/ID_ADRESSE_File_applet1_8_v4.pdf
#

_utf8 = set("""
carddata_os_number
carddata_os_version
carddata_soft_mask_number
carddata_soft_mask_version
carddata_appl_version
carddata_glob_os_version
carddata_appl_int_version
carddata_pkcs1_support
carddata_key_exchange_version
carddata_appl_lifecycle
issuing_municipality
surname
firstnames
first_letter_of_third_given_name
nationality
location_of_birth
date_of_birth
nobility
address_street_and_number
address_zip
address_municipality
member_of_family
""".split())

_ascii = set("""
card_number
validity_begin_date
validity_end_date
national_number
gender
document_type
special_status
duplicata
special_organization
date_and_country_of_protection
""".split())

_binary = set("""
chip_number
photo_hash
basic_key_hash
carddata_appl_version
""".split())

_blob = set("""
PHOTO_FILE
DATA_FILE
ADDRESS_FILE
CERT_RN_FILE
SIGN_DATA_FILE
SIGN_ADDRESS_FILE
BASIC_KEY_FILE
Authentication
Signature
CA
Root
""".split())


# the following fields caused encoding problems, so we ignore them for
# now:
# carddata_serialnumber
# carddata_comp_code


def eid2dict(certs=False):
    """
    Retrieve data and certificates from Belgian Eid
    Using the middleware to interface with card

    Parameters:
        certs: bool
            False: certificates are now retrieved, faster
            True: certificates are retrieved, slower
            
    """
    if 'PYKCS11LIB' not in os.environ:
        if platform.system().lower() == 'linux':
            os.environ['PYKCS11LIB'] = 'libbeidpkcs11.so.0'
        elif platform.system().lower() == 'darwin':
            # TODO: path for macos is "/Library/Belgium Identity Card/Pkcs11/beid-pkcs11.bundle/Contents/MacOS/libbeidpkcs11.dylib"
            os.environ['PYKCS11LIB'] = 'libbeidpkcs11.dylib'
        else:
            os.environ['PYKCS11LIB'] = 'beidpkcs11.dll'

    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load()

    slots = pkcs11.getSlotList()

    data = dict(
        success=False,
        message="Could not find any reader with a card inserted")

    # if len(slots) == 0:
    #     quit("No slot available")

    for slot in slots:
        try:
            sess = pkcs11.openSession(slot)
        except PyKCS11Error:
            continue
            # data.update(error=str(e))
            # quit("Error: {}".format(e))

        # print(dir(sess))
        try:
            # Get all data and certificate objects from Eid card
            dataobjs = sess.findObjects([(CKA_CLASS, CKO_DATA)])
            if certs == True:
                certobjs = sess.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
                objs = dataobjs + certobjs
            else:
                objs = dataobjs
        except PyKCS11Error as e:
            data.update(message=str(e))
            break
            # print(len(objs))
        # print(type(objs[0]), dir( objs[0]), objs[0].to_dict())
        for o in objs:
            label = sess.getAttributeValue(o, [CKA_LABEL])[0]
            value = sess.getAttributeValue(o, [CKA_VALUE])
            if len(value) == 1:
                # value = ''.join(chr(i) for i in value[0])
                value = bytes(value[0])
                try:
                    if label in _utf8:
                        value = value.decode('utf-8')
                        data[label] = value
                    elif label in _ascii:
                        value = value.decode('ascii')
                        data[label] = value
                    elif label in _binary:
                        value = value.hex()
                        data[label] = value
                    elif label in _blob:
                        value = base64.b64encode(value)
                        value = value.decode('ascii')
                        data[label] = value
                except UnicodeDecodeError:
                    print("20180414 {} : {!r}".format(label, value))
        data.update(success=True)
        data.update(message="OK")
    return data

@app.get("/beid")
def read_beid(certs: bool = False):
    result = eid2dict(certs=certs)
    return result