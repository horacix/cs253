from google.appengine.ext import db

class Page(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
