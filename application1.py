#!usr/bin/env python 3
#this modules contains all the routes for the functioning

from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import random
import string
import json
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///itemscatalog.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine
# connect to database and create database session
DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/')
@app.route('catalog')
@app.route('catalog/items/')
def home():
    """Route to home"""

    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template('index.html', categories=categories, items=items)


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in rante(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state, cleint_id=CLIENT_ID)

# connect to the google sign-in oAuth method
app.route('/gconnect', methods=['POST'])
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
        response = make_response(json.dumps("Token's user ID doesn't match given use ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # store the access toekn in the session for later userls

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # get user information
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
# see if user exist in database
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

# show welcome screen upon login

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# disconnect Google Account


def gdisconnect():
    # only disconnect the connected users
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s % access_token'
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# End session and log out current users
app.route('/logout')
def logout():
    """Log out the currently connected user."""

    if 'username' in log_session
        gbdisconnect()
        del login_session['gplus_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have been successfully logged out!")
        return redirect(url_for('home'))
    else:
        flash("Please log out! You are not logged in!")
        return redirect(url_for('home'))

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

def get_user_info(user_id):
    """get user information by user_id the user id and returns users details"""

    user = session.query(User).filter_by(id=user_id).one()
    return user

def get_user_id(email):
    """get user id by email  -email(str): the email of the user"""

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# add a new category
@app.route("/catalog/category/new/", methods=['GET', 'POST'])
def add_category():
    """add new category"""

    if 'username' not in login_session:
        flash("Please login in to continue.")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        if request.form['new-category-name'] == '':
            flash("Please make and entry")
            return redirect(url_for('home'))

        category = session.query(Category).\
            filter_by(name=request.form['new-category-name']).first()
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
        return render_template('new_category.html')


@app.route("/catalog/item/new/", methods=['GET', 'POST'])
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
        categories = session.query(Category).
                filter.by(user_id=login_session['user_id']).all()
        return render_template(
                'new_item.html',
                 items=items,
                 catergories=categories
        )

#edit existing items
@app.route("/catalog/item/<int:item_id>/edit/", methods=['GET', 'POST'])
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
                'update_item.html',
                item=item,
                categories=categories
            )

#delete existing items
@app.route("/catalog/item/<int:item_id>/delete/", methods=['GET', 'POST'])
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



# Show items in certain category
@app.route("/catalog/category/<int:category_id>/items/",
            methods=['GET', 'POST'])
def show_items_in_category(category_id):
    """Show items in a certain category"""

    if not exists_category(category_id):
        flash("Unable to Process Right Now")
        return redirect(url_for('home'))

    category = session.query(Category).filter_by(id=category_id).first()
    items = session.query(Item).filter_by(category_id=category_id).all()
    total = session.query(Item).filter_by(category_id=category_id).count()
    return render_template(
        'items.html',
        category=category,
        items=items,
        total=total
    )


# Edit a category
@app.route("/catalog/category/<int:category_is>/edit/",
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


    # if logged in user does not have authorization to edit the category redirect
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
        return render_template('edit_category.html', category=category)

# delete a category
@app.route("/catalog/category/<int:category_id>/delete/",
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


    # if logged in user does not have authorization to edit the category redirect
    if login_session['user_id'] != category.user_id:
        flash("Unable to Process your request Right Now")
        return redirect(url_for('home'))

    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash("Category was Deleted")
        return redirect(url_for('home'))
    else:
        return render_template('delete_category.html', category=category)

# Adding JSON ENDPOINTS
# Return JSON of all the items in the catalog and particular categaory
@app.route("/api/v1/catalog,json")
def show_catalog_json():
    """return JSON of all items in catalog"""

    items = session.query(Item).order_by(Item_id.desc())
    return jsonify(catalog=[i.serialize for i in items])


# retun JSOn of a particular item in catalog
@app.route("/api/v1/catergories/<int:category_id>/item/<int:item_id>/JSON")
def catalog_item_json(category_id, item_id):
    """return json of particular item in catalog"""

    if exists_category(category_id) and exists_item(item_id):
        item = session.query(Item)\
                .filter_by(id=item_id, category_id=category_id).first()
        if item is not None:
            return jsonify(item=item.serialize)
        else:
            return jsonify(error='item {} does not belong to category {}.'.format(item_id, category_id))
    else:
        return jsonify(error='The item or the category does not exist')


@app.route("/api/v1/categories/JSON")
def categories_json():

    categories = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in categories])


if __name__ == "__main__":
    app.secret_key = 'Dc2YRqHx88zKMVGj4SWxA0W-'
    app.debug = True
    app.run(host='0.0.0.0.', port=5000)
