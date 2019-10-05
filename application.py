#!usr/bin/catalog2/miche

from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask import flash, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup.py import Base, User, Item, Category


app = Flask(__name__)

#connect engine to database and create database session
engine = create_engine('sqlite:///itemcatalog.db',
                       connect_args={'check_same_thread': False}

#bind the above engine to session
DBSession = sessionmaker(bind=engine)
#create session object
session = DBSession()


#redirect to Login in Page
@app.route('/')
@app.route('/catalog/')
@app.route('/catalog/items/')
def home():
    """route to homepage"""

    items = session.query(Item).all()
    categories = session.query(Category).all()
    return render_template('index.html', categories=categories, items=items) # will link html file and object

#create new user
def create_user(login_session):
    """"create a new use login_session (dict): The login session"""

    new_user = User(
        name=login_session['usename'],
        email=login_session['email'],

    )

    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email'])
    return user.id

def get_user_info(user_id):
    """get user information by id user_id (int): the user id and returns users details"""

    user = session.query(User).filter_by(id=user_id).one()
    return user

def get_user_id(email):
    """get user id by email  -email(str): the email of the user"""

    try:
        user = session.query(User).filter_by(email=email).one()
        return user_id
    except:
        return None





#add a new category
@app.route('/catalog/catalog/new/', methods=['GET' , 'POST'])
def add_category():
    """add new category"""

    if 'username' not in log_session:
        flash("Please login in to continue.")
        return redirect(url_for('login'))
    elif request.method == "POST":
        if request.form['new-category-name'] == '':
            flash("Please make and entry")
            return redirect(url_for('home'))


    category = session.query(Category).\filter_by(name=request.form['new-category-name']).first()
    if category is None:
        flash("The category not chosen")
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

    #Create new item
@app.route('/catalog/item/new/', methods=['GET' , 'POST'])
def add_item():
    """Create a new item """

    if 'username' not in log_session:
        flash("Please login in to continue.")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        #check to see if item exist - if not displat error
        item = session.query(Item)/filter_by(name=request.form['name']).first()
        if item:
            if item.name == request.form['name']:
                flash('The item already exist')
                return redirect(url_for("add_item"))
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
        items = session.query(Item).\filter.by(user_id=login_session['user_id']).all()
        categories = session.query(Category).\filter_by(user_id=login_session['user_id']).all()
        return render_template('new_item.html', items=items, catergories=categories)

    #create  ####### #329 -  go back dd through #415

        #Edit existing items
@app.route('/catalog/item/<int:item_id>edit/', methods=['GET' , 'POST'])
def edit_item(item_id):
    """edit existing item"""

    if 'username' not in login_session:
        flash("Please log in")
        return redirect(url_for('login'))

    if not exists_item(item.id):
        flash("Unable to Process right now")
        return redirect(url_for('home'))

    item = session.query(Item).filter_by(id=item.id).first()
        if login_session['user_id'] != item.user.id:
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
            return redirect(url_for('edit-item', item_id=item_id))
            else:
        categories = session.query(Category).\filter_by(user_id-login_session['user_id']).all()
            return render_template(
                'update_item.html', items=items, categories=categories
                )
        #Delete existing item
@app.route('/catalog/item/<int:item_id>/delete/', methods=['GET' , 'POST'])
def delete_item(item_id):
    """Delete existing item"""

    If 'username' not in login_session:
        flash("Please log In")
        return redirect(url_for('login'))

    if not exists_item(item_id):
        flash("Unable to Process Right Now")
        return redirect(url_for('home'))

    item = session.query(item).filter_by(id=item_id).first()
        if login_session['user_id'] != item.user_id:
            flash("You must login to access this page")
            return redirect(url_for('home'))

        if request.method == 'POST':
            session.delete(Item)
            session.commit()
            flash("Item has been Deleted")
            return redirect(url_for('home'))
        else:
            return render_template('delete.html', items=items)

        #Show items in certain category
@app.route('/catalog/category/<int:category_id>/items/')
def show_items_category(category_id):
        """Show items in a certain category"""

    if not exists_category(category_id):
        flash("Unable to Process Right Now")
        return redirect(url_for('home'))

    category = session.query(Category).filter_by(id=categpry_id).first()
        items = session.query(Item).filter_by(category_id).all()
        total = session.query(Item).filter_by(category_id=category_id).count()
        return render_template(
            'items.html', category=category, items=items, total=total)

#Edit a category
@app.route('/catalog/category/<int:category_is>/edit/', methods=['GET' , 'POST'])
def edit_category(category_id):
    """edit a category"""

    category = session.query(Category).filter_by(id=category_id).first()

    If 'username' not in login_session:
        flash("Please log In")
        return redirect(url_for('login'))

    if not exists_category(category_id):
        flash("Unable to Process Right Now")
        return redirect(url_for('home'))

#if logged in user does not have authorization to edit the category redirect
    if login_session['user_id'] != category.user_id:
        flash("Unable to Process your request Right Now")
        return redirect(url_for('home'))

        if request.method == 'POST':
            if request.form['name']:
                category.name = request.form['name']
                session.add(category)
                session.commit()
                flash('Category updated sucessfully')
                return redirect(url_for('show_items_category', category_id=category.id))

            else:
                return render_template('edit_category.html', category=category)


    #delete a category
@app.route('/catalog/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def delete_category(category_id):
    """Delete a category"""

    category = session.query(Category).filter_by(id=category_id).first()

    If 'username' not in login_session:
        flash("Please log In")
        return redirect(url_for('login'))

    if not exists_category(category_id):
        flash("Unable to Process Right Now")
        return redirect(url_for('home'))

#if logged in user does not have authorization to edit the category redirect
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


                #Adding JSON ENDPOINTS
#Return JSON of all the items in the catalog and particular categaory
@app.route('/api/v1/catalog,json')
def show_catalog_json():
    """return JSON of all items in catalog"""

    items = session.query(Item).order_by(Item_is.desc())
    return jsonify(catalog=[1.serialize for i in items])

@app.route('/api/v1/catergories/<int:category_id>/item/<int:item_id>/JSON')
def catalog_item_json(category_id, item_id):
    if exists_category(category_id) and exists_item(item_id):
        item = session.query(Item)\.filter_by(id=item_id, category_id=category_id).first()
        if item is not None:
            return jsonify(error='item {} does not belong to category {}.'.format(item_id, category_id))
    else:
        return jsonify(error='The item or the category does not exist')

@app.route('/api/v1/categories/JSON')
def categories_json():

    categories = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in categories])



if __name__ == "__main__":
    app.debug = True
    app.run(host = '0.0.0.0.', port = 5000)
