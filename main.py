#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2

from user import User
from page import Page

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
    autoescape=True)

SECRET = "palabra super secreta"
DEBUG = True

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def generate_cookie(self, val):
        import hmac
        return str("%s|%s" % (val, hmac.new(SECRET, str(val)).hexdigest()))

    def get_cookie(self, cookie):
        if not cookie:
            return None
        val = cookie.split('|')[0]
        if self.generate_cookie(val) == cookie:
            return val
        return None

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        cookie = self.request.cookies.get('user')
        uid = self.get_cookie(cookie)
        self.user = uid and User.get_by_id(int(uid))

class Signup(Handler):
    username_error = ""
    password_error = ""
    verify_error = ""
    email_error = ""

    def render_form(self, username="",email=""):
        self.render('signup.html', username=username,
            username_error=self.username_error,
            password_error=self.password_error,
            verify_error=self.verify_error,
            email=email,
            email_error=self.email_error)

    def validate(self, username, password, verify, email):
        import re

        valid = True
        
        if not re.match(r"^[a-zA-Z0-9_-]{3,20}$", username):
            self.username_error = "That's not a valid username."
            valid = False

        # check not repeated username
        user = User.get_by_username(username)
        if user:
            self.username_error = "The user already exists."
            valid = False

        if not re.match(r"^.{3,20}$", password):
            self.password_error = "That wasn't a valid password."
            valid = False
        else:
            if not verify == password:
                self.verify_error = "Your passwords didn't match."
                valid = False

        if email.strip() != "" and not re.match(r"^[\S]+@[\S]+\.[\S]+$", email):
            self.email_error = "That's not a valid email."
            valid = False
        
        return valid

    def get(self):
        self.render_form()

    def post(self):
        from cgi import escape
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        username = escape(user_username)
        email = escape(user_email)
        if self.validate(username, user_password, user_verify, email):
            u = User(username=username,
                password_hash=User.get_password_hash(user_password), email=email)
            u.put()
            self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' %
                self.generate_cookie(u.key().id()))
            self.redirect('/')
        else:
            self.render_form(username, email)

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')

        user = User.get_by_username(user_username)
        if user and user.valid_password(user_password):
            self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' %
                self.generate_cookie(user.key().id()))
            self.redirect('/')
        else:
            self.render('login.html', login_error = 'Invalid login')

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
        self.redirect('/')

class EditPage(Handler):
    def get(self, page_name):
        if not self.user:
            self.redirect('/login')
        page = Page.get_by_name(page_name)
        content = ''
        if page:
            content = page.content
        self.render('edit.html', content=content)

    def post(self, page_name):
        content = self.request.get('content')
        page = Page.get_by_name(page_name)
        if page:
            page.content = content
        else:
            page = Page(name=page_name, content=content)
        page.put()
        self.redirect(page_name)

class WikiPage(Handler):
    def get(self, page_name):
        page = Page.get_by_name(page_name)
        if page:
            self.render('page.html', content=page.content,
                name=page.name,
                user=self.user)
        else:
            self.redirect('/_edit' + page_name)
		

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=DEBUG)