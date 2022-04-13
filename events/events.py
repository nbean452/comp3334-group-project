# https://python-adv-web-apps.readthedocs.io/en/latest/flask_db2.html
# https://satyakide.com/2019/02/11/encryption-decryption-json-api-flask-framework-in-python-crossover-between-reality-stone-time-stone-in-python-verse/
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
# https://stackoverflow.com/questions/28447126/exportkey-function-not-recognized-in-pycrypto-2-6-1python-2-7-6-ubuntu14-04
# https://stackoverflow.com/questions/70630141/pycryptodome-aes-cbc-failing-to-decrypt-a-string

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5

app = Flask(__name__)

# the name of the database; add path if necessary
db_name = 'database.db'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_name

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# this variable, db, will be used for all SQLAlchemy commands
db = SQLAlchemy(app)

class theEvents(db.Model):
    __tablename__ = 'socks'
    id = db.Column(db.Integer, primary_key=True)
    artID = db.Column(db.Integer)
    eventDate = db.Column(db.String)
    fromID = db.Column(db.Integer)
    toID = db.Column(db.Integer)
    transAmount = db.Column(db.Integer)

@app.route('/')
def fetch():
    try:
        events = theEvents.query.order_by(theEvents.id).all()
        for i in events:
            b = i.artID.encode("UTF-8")
            ciphertext = encrypt_test(b)
            # put back to database
            b = i.eventDate.encode("UTF-8")
            ciphertext = encrypt_test(b)
            b = i.fromID.encode("UTF-8")
            ciphertext = encrypt_test(b)
            b = i.toID.encode("UTF-8")
            ciphertext = encrypt_test(b)
            b = i.transAmount.encode("UTF-8")
            ciphertext = encrypt_test(b)
        return
    except Exception as e:
        # e holds description of the error
        error_text = "<p>Error message:<br>" + str(e) + "</p>"
        hed = '<h1>Something is broken.</h1>'
        return hed + error_text

@app.route('/')
def create_rsa_key():
    key = RSA.generate(2048)

    private = key.exportKey('PEM')
    public = key.publickey()

    with open("private.pem", "wb") as f:
        f.write(private)
    with open("public.pem", "wb") as f:
        f.write(public.exportKey('PEM'))


@app.route('/')
def RSAencryption(b):
    public = RSA.importKey(
        open("public.pem").read()
    )
    cipher = PKCS1_OAEP.new(public)

    ciphertex = cipher.encrypt(b)
    #print(len(ciphertex), ciphertex)

@app.route('/')
def RSAdecryption(ciphertex):
    private = RSA.importKey(open('private.pem').read())
    cipher = PKCS1_OAEP.new(private)
    message = cipher.decrypt(ciphertex)
    #print(message)



if __name__ == '__main__':
    app.run(debug=True)