from google.appengine.ext import db

class Page(db.Model):
    name = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @staticmethod
    def get_by_name(name):
        pages = db.GqlQuery("select * from Page where name = :1",
            name)
        if pages.count() > 0:
            return pages[0]
        return None
