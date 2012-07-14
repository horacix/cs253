from google.appengine.ext import db

class Page(db.Model):
    name = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @staticmethod
    def get_by_name(name):
        p = Page.all().filter('name =', name).get()
        return p
