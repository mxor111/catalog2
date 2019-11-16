
from functools import wraps
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Fun Catalog"

engine = create_engine('postgresql:///var/www/catlog/catlog2/itemscatalog.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine
# connect to database and create database session
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Login required decorator


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function

# Adding JSON ENDPOINTS
# Return JSON of all the items in the catalog and particular categaory
@app.route('/api/v1/catalog,json')
def showCatalogJSON():
    """return JSON of all items in catalog"""

    items = session.query(Item).order_by(Item_id.desc())
    return jsonify(Item=[i.serialize for i in items])


@app.route('/api/v1/catergories/<int:category_id>/item/<int:item_id>/JSON')
def catalogItemJSON(category_id, item_id):
    """return json of particular item in catalog"""
    Item = session.query(Item).filter_by(id=Item_id).one()
    return jsonify(Item=Item.serialize)


@app.route('/api/v1/categories/JSON')
def categoriesJSON():

    categories = session.query(Category).all()
    return jsonify(Categories=[i.serialize for i in categories])


@app.route('/')
@app.route('/catalog/')
@app.route('/catalog/items/')
def home():
    """Route to home page with all categories and recently added items"""

    categories = session.query(Category).all()
    items = session.query(Item).order_by(Item.id.desc())
    quantity = items.count()
    return render_template('index.html', categories=categories, items=items)


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in rante(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state, cleint_id=CLIENT_ID)


def create_user(login_session):
    """"create a new use login_session (dict): The login session"""

    new_user = User(
        name=login_session['username'],
        picture=login_session['picture'],
        email=login_session['email']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


@app.route('/catalog/category/new', methods=['GET', 'POST'])
def add_category():
    """add new category"""

    if 'username' not in login_session:
        flash("Please login in to continue.")
        return redirect(url_for('login'))

    elif request.method == 'POST':
        if request.form['new-category-name'] == '':
            flash("Please make and entry")
            return redirect(url_for('home'))

        category = session.query(Category).filter_by(name=request.form
                                                     ['new-category-name']).first()
        if category is not None:
            flash('The category not chosen')
            return redirect(url_for('add_category'))

        new_category = Category(
            name=request.form['new-category-name'],
            user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        flash('New category %s sucessfully created!' % new_category.name)
        return redirect(url_for('home'))
    else:
        return render_template('new-category.html')


@app.route('/catalog/category/<int:category_is>/edit/',
           methods=['GET', 'POST'])
def edit_category(category_id):
    """edit a category"""
    category = session.query(Category).filter_by(id=category_id).first()

    if 'username' not in login_session:
        flash("Please log In")
        return redirect(url_for('login'))

    if not exists_category(category_id):
        flash("Unable to Process Right Now")
        return redirect(url_for('home'))

    # logged in user does not have authorization to edit the category redirect
    if login_session['user_id'] != category.user_id:
        flash("Unable to Process your request Right Now")
        return redirect(url_for('home'))

    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
        session.add(category)
        session.commit()
        flash('Category updated sucessfully')
        return redirect(url_for('show_items_in_category',
                                category_id=category.id))
    else:
        return render_template('edit-category.html', category=category)


# delete a category
@app.route('/catalog/category/<int:category_id>/delete/',
           methods=['GET', 'POST'])
def delete_category(category_id):
    """Delete a category"""

    category = session.query(Category).filter_by(id=category_id).first()

    if 'username' not in login_session:
        flash("Please log In")
        return redirect(url_for('login'))

    if not exists_category(category_id):
        flash("Unable to Process Right Now")
        return redirect(url_for('home'))

    # logged in user does not have authorization to edit the category redirect
    if login_session['user_id'] != category.user_id:
        flash("Unable to Process your request Right Now")
        return redirect(url_for('home'))

    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash("Category was Deleted")
        return render_template('delete-category.html', category=category)


# Show Items in category
@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def showCategoryItems(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    categories = session.query(Category).all()
    items = session.query(Item).filter_by(
        category_id=category_id).order_by(Item.id.desc())
    quantity = items.count()
    return render_template('new-item.html', categories=categories, category=category, items=items, quantity=quantity)


@app.route('/catalog/item/new/', methods=['GET', 'POST'])
def add_item():
    """Create a new item. This will list all login uuser created """

    if 'username' not in log_session:
        flash("Please login in to continue.")
        return redirect(url_for('login'))
    elif request.method == 'POST':

        item = session.query(Item).filter_by(name=request.form['name']).first()
        if item:
            if item.name == request.form['name']:
                flash('The item already exist')
                return redirect(url_for('add_item'))
        new_item = Item(
            name=request.form['name'],
            category_id=request.form['category'],
            description=request.form['description'],
            user_id=login_session['user_id']
        )
        session.add(new_item)
        session.commit()
        flash('New item created')
        return redirect(url_for('home'))
    else:
        items = session.query(Item).\
            filter.by(user_id=login_session['user_id']).all()
        categories = session.query(Category).filter.by(
            user_id=login_session['user_id']).all()
        return render_template(
            'new-item.html',
            items=items,
            catergories=categories
        )


# edit existing items
@app.route('/catalog/item/<int:item_id>/edit/', methods=['GET', 'POST'])
def edit_item(item_id):
    """edit existing item"""

    if 'username' not in login_session:
        flash("Please log in")
        return redirect(url_for('login'))

    if not exists_item(item_id):
        flash("Unable to Process right now")
        return redirect(url_for('home'))

    item = session.query(Item).filter_by(id=item_id).first()
    if login_session['user_id'] != item.user_id:
        flash("You must log in to access this page")
        return redirect(url_for('home'))

    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category']:
            item.category_id = request.form['category']
        session.add(item)
        session.commit()
        flash('Item sucessfully Added')
        return redirect(url_for('edit_item', item_id=item_id))
    else:
        categories = session.query(Category).\
            filter_by(user_id=login_session['user_id']).all()
        return render_template(
            'update-item.html',
            item=item,
            categories=categories
        )

# delete existing items
@app.route('/catalog/item/<int:item_id>/delete/', methods=['GET', 'POST'])
def delete_item(item_id):
    """Delete existing item"""

    if 'username' not in login_session:
        flash("Please log In")
        return redirect(url_for('login'))

    if not exists_item(item_id):
        flash("Unable to Process Right Now")
        return redirect(url_for('home'))

    item = session.query(Item).filter_by(id=item_id).first()
    if login_session['user_id'] != item.user_id:
        flash("You must login to access this page")
        return redirect(url_for('home'))

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Item has been Deleted")
        return redirect(url_for('home'))
    else:
        return render_template('delete.html', item=item)


# Connect to facebook
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    # exchange client token for long-lived server-side sendTokenServer
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # use token to get user info from api
    userinfo_url = "https://graph.facebook.com/v4.0/me"
    # strip expire tage from acces tokeninf
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v4.0/me?fields=id%2Cname%2Cemail%2Cpicture&access_token=' + access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    # login provider
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    login_session['access_token'] = access_token

    # get user picture - facebook uses seperate api call to retrieve
    url = 'https://gaphe.facebook.com/v4.0.me.picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["picture"]["data"]["url"]

    # see if user exist
    user_id = getUserId(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1> Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'], 'success')
    return output


# disconnect FB login
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# connect to the google sign-in oAuth method
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # validate token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # obtain authroization code
    code = request.data

    try:
        # the authorization code into creditals object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Fail to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check that the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given use ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # store the access toekn in the session for later userls

    login_session['access_token'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # get user information
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
# see if user exist in database
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if not create new user
    user_id = getUserId(login_session)['email']
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; '
    output += 'border-radius: 150px; '
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as %s" % login_session['username'])
    return output


# disconnect Google Account
@app.route('/gbdisconnect')
def gdisconnect():
    # only disconnect the connected users
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # execute HTTP get to revoke current tokenin
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # reset the user's session
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # give toeken invalid
        response = make_response(
            json.dumps('Failed to revoke token for given user'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gbdisconnect()
            if 'gplus_id' in login_session:
                del login_session['gplus_id']
            if 'credentials' in login_session:
                del login_session['credentials']
            if login_session['provider'] == 'facebook':
                fbdisconnect()
                del login_session['facebook_id']
            if 'username' in login_session:
                del login_session['username']
            if 'email' in login_session:
                del login_session['email']
            if 'picture' in login_session:
                del login_session['picture']
            if 'user_id' in login_session:
                del login_session['user_id']
            del login_session['provider']
            flash("You have successfully been logged out.", 'success')
            return redirect(url_for('home'))
        else:
            flash("You were not logged in")
            return redirect(url_for('home'))


if __name__ == "__main__":
    app.secret_key = 'Dc2YRqHx88zKMVGj4SWxA0W-'
    app.debug = True
    app.run(host='0.0.0.0.', port=5000)
