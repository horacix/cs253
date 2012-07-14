from google.appengine.ext import db

class Page(db.Model):
    name = db.TextProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @staticmethod
    def get_by_name(name):
        real_name = name
#        if name == '':
#            real_name = '*root'
        pages = db.GqlQuery("select * from Page where name = :1",
            real_name)
        if pages.count() > 0:
            return pages[0]
        return None
