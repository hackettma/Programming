
import os
import re
import cgi
import time
import webapp2
import jinja2
from google.appengine.ext import db
import hashlib
import hmac
import urllib2
import random
from string import letters
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

def valid_username(user_name):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    if USER_RE.match(user_name):
        return True
    else:
        return False

def valid_pwd(pwd):
    PWD_RE = re.compile(r"^.{3,20}$")
    if PWD_RE.match(pwd):
        return True
    else:
        return False

def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    if email == "":
      return True
    elif EMAIL_RE.match(email):
        return True
    else:
        return False

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    params['user'] = self.user
    return render_str(template, **params)

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
  pth = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)



class Signup(BaseHandler):
  def get(self, user_name="", err_usr="", err_pwd="", err_cnfrm="", err_eml=""):
    self.render("user_form.html", user_name=user_name, err_usr=err_usr, err_pwd=err_pwd, err_cnfrm=err_cnfrm, err_eml=err_eml)

  def post(self):
      user_name_in = self.request.get('username')
      user_pwd = self.request.get('password')
      user_cnfrm_pwd = self.request.get('verify')
      user_email = self.request.get('email')

      error_usr_txt = "Invalid Username"
      error_pwd_txt = "Invalid Password"
      error_cnfrm_txt = "Password does not match"
      error_email_txt = "Invalid email address"
      out_params = {}
      out_params['username'] = user_name_in


      user = User.by_name(user_name_in)

      if valid_username(user_name_in) and not user:
        if valid_pwd(user_pwd):
          if user_pwd == user_cnfrm_pwd:
            if valid_email(user_email):
              user = User.register(user_name_in, user_pwd, user_email)
              user.put()
              self.login(user)
              self.redirect("/")
            else:
              out_params['err_eml'] = error_email_txt
              self.render('user_form.html', **out_params)    
          else:
            out_params['err_cnfrm'] = error_cnfrm_txt
            self.render('user_form.html', **out_params)
        else:
          out_params['err_pwd'] = error_pwd_txt
          out_params['err_usr'] = error_usr_txt
          self.render('user_form.html', **out_params)
      else:
        out_params['err_usr'] = error_usr_txt
        self.render('user_form.html', **out_params)

class Login(BaseHandler):

  def get(self, user_name="", err_usr="", err_pwd=""):
    self.render("login_form.html", user_name=user_name, err_usr=err_usr, err_pwd=err_pwd)

  def post(self):
    username = self.request.get('username')
    pwd = self.request.get('password')

    user = User.login(username, pwd)
    if user:
      self.login(user)
      self.redirect('/')
    else:
      params = {'user_name': username, 'err_usr':"Username invalid", 'err_pwd': "Password Invalid"}
      self.render("login_form.html",**params)


class Logout(BaseHandler):
  def render_front(self):
    self.render("index.html")


  def get(self):
    ref = self.request.referrer
    l = ref.split('/')
    prev_page = l[-1]
    self.logout()
    self.redirect('/' + prev_page)

class EditPage(BaseHandler):

  def render_front(self, content=""):
    self.render("wiki_form.html", content=content)
  
  def get(self, wikipage=""):
    if self.user:
      if wikipage == "":
          ref = self.request.referrer
          l = ref.split('/')
          prev_page = l[-1]
          if prev_page == "":
            wikipage = '/'
          else:
            wikipage = '/'+prev_page
            
          self.redirect('/_edit'+wikipage)
      wikis = db.GqlQuery("SELECT * FROM Wiki ORDER BY created DESC")
        
      for wiki in wikis:
        if wiki.pth == wikipage:
          self.render_front(content=wiki.content)
          break
      else:
        self.render_front()
      
    else:
        self.redirect('/login')

  def post(self, wikipage=""):
    if wikipage == "":
      wikipage = '/'
    content_post = self.request.get('content')

    w = Wiki(pth=wikipage, content=content_post)
    w.put()
    self.redirect('%s' %wikipage)
    

class WikiPage(BaseHandler):

  def render_front(self, content=""):
    self.render("wiki.html", content=content)
  
  def get(self, wikipage=""):
    if wikipage == "":
      wikipage ='/'
    wikis = db.GqlQuery("SELECT * FROM Wiki ORDER BY created DESC")
    for wiki in wikis:
      if wiki.pth == wikipage:
        self.render_front(content=wiki.content)
        break
    else:
        self.redirect('/_edit' + wikipage)


class TestPage(BaseHandler):
  def get(self, wikipage=""):
    ref = self.request.referrer
    l = ref.split('/')
    self.response.out.write(l)
    



#######################################################################################
###########URL HANDLER#################################################################            
PAGE_RE = '(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([ ('/', WikiPage),
                                ('/signup', Signup),
                                ('/login', Login),
                                ('/logout', Logout),
                                ('/test', TestPage),
                                ('/_edit', EditPage),
                                ('/_edit' + PAGE_RE, EditPage),
                                (PAGE_RE, WikiPage),
                                ],
                              debug=True)


















    













