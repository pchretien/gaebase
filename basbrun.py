from google.appengine.ext import db

class User(db.Model):
    regkey = db.StringProperty(required=True)
    email = db.StringProperty(required=True)
    newemail = db.StringProperty()
    password = db.StringProperty(required=True)
    firstname = db.StringProperty(default="")
    lastname = db.StringProperty(default="")
    activated = db.IntegerProperty(default=0)
    created = db.DateTimeProperty(auto_now_add=True)