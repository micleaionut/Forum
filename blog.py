# importing all modules
import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from webapp2 import WSGIApplication
from google.appengine.ext import db

# implement jinja
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Blog handler class which have different actions like login logout and init
class BlogHandler(webapp2.RequestHandler):
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


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# Main page
class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# comment model
class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)
    user_name = db.TextProperty(required=True)


# like model
class Like(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)


# post model
class Post(db.Model):
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)

    def render(self, current_user_id):
        key = db.Key.from_path('User', int(self.user_id), parent=users_key())
        user = db.get(key)

        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html",
                          p=self,
                          current_user_id=current_user_id,
                          author=user.name)


# page with all posts
class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery(
            "select * from Post where user_id > 1")

        self.render('front.html', posts=posts)


# edit for post
class EditPage(BlogHandler):
    def get(self):
        self.render('edit.html')


# post page
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())
        post = db.get(key)
        # get comments for this post
        comments = db.GqlQuery(
            "select * from Comment where ancestor is :1 order by created",
            key)

        if not post:
            self.error(404)
            return
        # render template permalink with posts and comments
        self.render("permalink.html", post=post, comments=comments)


# page for new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')
        # get the subject and content from form
        subject = self.request.get('subject')
        content = self.request.get('content')
        # insert in database
        if subject and content:
            p = Post(parent=blog_key(),
                     subject=subject,
                     content=content,
                     user_id=self.user.key().id())
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)


# Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)

# check valid username password and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# signup the user using checking functions
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html',
                        error_username=msg)
        else:
            u = User.register(self.username,
                              self.password,
                              self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


# login the user
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


# logout the user
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html',
                        username=self.user.name)
        else:
            self.redirect('/signup')


# edit the post
class EditPostHandler(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())
        post = db.get(key)
        # check if is the user and the post id same as logged one
        if self.user and self.user.key().id() == post.user_id:
            self.render('editpost.html',
                        subject=post.subject,
                        content=post.content,
                        post_id=post_id)

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You cannot edit this post.")

# save the post in database
    def post(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())
        post = db.get(key)

        if not self.user:
            return self.redirect('/login')

        if self.user and self.user.key().id() == post.user_id:
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                key = db.Key.from_path('Post',
                                       int(post_id),
                                       parent=blog_key())
                post = db.get(key)

                post.subject = subject
                post.content = content

                post.put()

                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "subject and content, please!"
                self.render("newpost.html",
                            subject=subject,
                            content=content,
                            error=error)

        else:
            self.write("You cannot edit this post.")


# delete post
class DeletePostHandler(BlogHandler):
    # get the post and check user id
    def get(self, post_id, post_user_id):
        if self.user and self.user.key().id() == int(post_user_id):
            key = db.Key.from_path('Post',
                                   int(post_id),
                                   parent=blog_key())
            post = db.get(key)
            post.delete()

            self.redirect('/blog')

        elif not self.user:
            self.redirect('/login')
# else redirect and show no access
        else:
            key = db.Key.from_path('Post',
                                   int(post_id),
                                   parent=blog_key())
            post = db.get(key)

            error = "You don't have permission to delete this post"
            self.render("permalink.html",
                        post=post,
                        error=error)


# like post
class LikePostHandler(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())
        post = db.get(key)
        # check if is the user logged in
        if self.user and self.user.key().id() == post.user_id:
            error = "Sorry, you cannot like your own post."
            self.render('base.html',
                        access_error=error)
        elif not self.user:
            self.redirect('/login')
        else:
            user_id = self.user.key().id()
            post_id = post.key().id()

            like = Like.all().filter('user_id =',
                                     user_id).filter('post_id =',
                                                     post_id).get()

            if like:
                self.redirect('/blog/' + str(post.key().id()))
    # add like
            else:
                like = Like(parent=key,
                            user_id=self.user.key().id(),
                            post_id=post.key().id())

                post.likes += 1

                like.put()
                post.put()

                self.redirect('/blog/' + str(post.key().id()))


# unlike the post
class UnlikePostHandler(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.write("You cannot dislike your own post")
        elif not self.user:
            self.redirect('/login')
        else:
            user_id = self.user.key().id()
            post_id = post.key().id()

            l = Like.all().filter('user_id =',
                                  user_id).filter('post_id =',
                                                  post_id).get()
            # - 1 the like from like
            if l:
                l.delete()
                post.likes -= 1
                post.put()

                self.redirect('/blog/' + str(post.key().id()))
            else:
                self.redirect('/blog/' + str(post.key().id()))


# add comment
class AddCommentHandler(BlogHandler):

    def get(self, post_id, user_id):
        if not self.user:
            self.render('/login')
        else:
            self.render("addcomment.html")

# add the comment in database
    def post(self, post_id, user_id):
        if not self.user:
            return
# save different values in columns of comments model
        content = self.request.get('content')

        user_name = self.user.name
        key = db.Key.from_path('Post',
                               int(post_id),
                               parent=blog_key())

        c = Comment(parent=key,
                    user_id=int(user_id),
                    content=content,
                    user_name=user_name)
        c.put()

        self.redirect('/blog/' + post_id)


# edit comment
class EditCommentHandler(BlogHandler):

    def get(self, post_id, post_user_id, comment_id):
        if self.user and self.user.key().id() == int(post_user_id):
            comment = Comment.get_by_id(int(comment_id))
            if comment:
                postKey = db.Key.from_path('Post',
                                           int(post_id),
                                           parent=blog_key())
                key = db.Key.from_path('Comment',
                                       int(comment_id),
                                       parent=postKey)
                comment = db.get(key)

                self.render('editcomment.html',
                            content=comment.content)
            else:
                self.write("This comment is no longer exist")

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You don't have permission to edit this comment.")

    def post(self, post_id, comment_user_id, comment_id):
        if not self.user:
            return

        if self.user and self.user.key().id() == int(comment_user_id):
            content = self.request.get('content')

            postKey = db.Key.from_path('Post',
                                       int(post_id),
                                       parent=blog_key())
            key = db.Key.from_path('Comment',
                                   int(comment_id),
                                   parent=postKey)
            comment = db.get(key)

            comment.content = content
            comment.put()

            self.redirect('/blog/' + post_id)

        else:
            self.write("You don't have permission to edit this comment.")


# delete comment
class DeleteCommentHandler(BlogHandler):

    def get(self, post_id, comment_user_id, comment_id):

        if self.user and self.user.key().id() == int(comment_user_id):
            postKey = db.Key.from_path('Post',
                                       int(post_id),
                                       parent=blog_key())
            key = db.Key.from_path('Comment',
                                   int(comment_id),
                                   parent=postKey)
            comment = db.get(key)
            comment.delete()

            self.redirect('/blog/' + post_id)

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You don't have permission to delete this comment.")


# first page with username displayed
class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html',
                        username=username)
        else:
            self.redirect('/unit2/signup')

app = WSGIApplication([('/', MainPage),
                       ('/unit2/rot13', Rot13),
                       ('/unit2/signup', Unit2Signup),
                       ('/unit2/welcome', Welcome),
                       ('/blog/?', BlogFront),
                       ('/blog/([0-9]+)', PostPage),
                       ('/blog/newpost', NewPost),
                       ('/blog/([0-9]+)/edit', EditPostHandler),
                       ('/blog/([0-9]+)/delete/([0-9]+)', DeletePostHandler),
                       ('/blog/([0-9]+)/like', LikePostHandler),
                       ('/blog/([0-9]+)/unlike', UnlikePostHandler),
                       ('/blog/([0-9]+)/addcomment/([0-9]+)',
                        AddCommentHandler),
                       ('/blog/([0-9]+)/([0-9]+)/editcomment/([0-9]+)',
                        EditCommentHandler),
                       ('/blog/([0-9]+)/([0-9]+)/deletecomment/([0-9]+)',
                        DeleteCommentHandler),
                       ('/signup', Register),
                       ('/login', Login),
                       ('/logout', Logout),
                       ('/unit3/welcome', Unit3Welcome),
                       ],
                      debug=True)
