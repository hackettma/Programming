
import os
import re
import cgi
import time
import webapp2
import jinja2
from google.appengine.ext import db
import hashlib
import urllib2
from xml.dom import minidom

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
secret = 'fart'


class BaseHandler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))  

  def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Wiki(db.Model):
  title = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)


class MainPage(BaseHandler):
  def render_front(self, wikis="", logged_in="", user=""):
    self.render("index.html", wikis=wikis)


  def get(self):
    wikis = db.GqlQuery("SELECT * FROM Wiki ORDER BY title ASC LIMIT 1")
    self.render_front(wikis=wikis)

class Signup(BaseHandler):
  def render_front(self):
    self.render("index.html")


  def get(self):
    self.render_front()

class Login(BaseHandler):
  def render_front(self):
    self.render("index.html")


  def get(self):
    self.render_front()

class Logout(BaseHandler):
  def render_front(self):
    self.render("index.html")


  def get(self):
    self.logout()
    self.render_front()

class EditPage(BaseHandler):

  def render_front(self, subject="", content="", error=""):
    self.render("wiki_form.html", subject=subject, content=content, error=error)
  
  def get(self, wikipage):
    wikis = db.GqlQuery("SELECT * FROM Wiki ORDER BY created DESC")
    for wiki in wikis:
      if wiki.title == wikipage[1:]:
        self.render_front(subject=wiki.title, content=wiki.content)
        break
    else:
        self.render_front(subject=wikipage[1:])

  def post(self, wikipage):
    title_post = self.request.get('subject')
    content_post = self.request.get('content')

    if title_post and content_post:
      w = Wiki(title=title_post, content=content_post)
      w.put()
      self.redirect('/%s' %title_post)
    else:
      self.render_front(self, subject=title_post, content=content_post, error="Please enter some content")

class WikiPage(BaseHandler):

  def render_front(self, subject="", content=""):
    self.render("wiki.html", subject=subject, content=content)
  
  def get(self, wikipage):
    wikis = db.GqlQuery("SELECT * FROM Wiki ORDER BY created DESC")
    for wiki in wikis:
      if wiki.title == wikipage[1:]:
        self.render_front(subject=wiki.title, content=wiki.content)
        break
    else:
        self.redirect('_edit' + wikipage)


class TestPage(BaseHandler):
  def get(self):
    self.response.out.write(self.request.get('title'))




#######################################################################################
###########URL HANDLER#################################################################            
PAGE_RE = '(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([ ('/', MainPage),
                                ('/signup', Signup),
                                ('/login', Login),
                                ('/logout', Logout),
                                ('/test', TestPage),
                                ('/_edit' + PAGE_RE, EditPage),
                                (PAGE_RE, WikiPage),
                                ],
                              debug=True)


















    













