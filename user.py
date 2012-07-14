from google.appengine.ext import db

class User(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=False)

    @staticmethod
    def generate_salt():
        import random
        import string
        return ''.join(random.sample(string.letters, 5))

    @staticmethod
    def get_password_hash(pwd, salt=None):
        import hashlib
        if not salt:
            salt = User.generate_salt()
        return "%s,%s" % (hashlib.sha256(pwd+salt).hexdigest(), salt)

    def valid_password(self, pwd):
        salt = self.password_hash.split(',')[1]
        if User.get_password_hash(pwd, salt) == self.password_hash:
            return True
        return False

    @staticmethod
    def get_by_username(username):
        users = db.GqlQuery("select * from User where username = :1",
            username)
        if users.count() > 0:
            return users[0]
        return None
