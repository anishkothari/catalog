from flask import Flask, render_template, url_for, make_response, redirect, request, flash, jsonify
from flask import session as login_session
from flask.ext.bootstrap import Bootstrap
import random, string, requests, json, httplib2
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError, AccessTokenCredentials
from database_setup import Base, Wardrobe, Clothing, User

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Wardrobe"

app = Flask(__name__)
bootstrap = Bootstrap(app)
engine = create_engine('sqlite:///wardrobe.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('showWardrobes'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/')
@app.route('/wardrobe')
def showWardrobes():
    '''query the database and retrieve all wardrobes,
    then displaying them with the appropriate template'''
    wardrobes = session.query(Wardrobe).all()
    if 'username' not in login_session:
        return render_template('publicwardrobes.html', wardrobes=wardrobes)
    return render_template('wardrobes.html', wardrobes = wardrobes)

@app.route('/wardrobe/new', methods=['GET', 'POST'])
def newWardrobe():
    if 'username' not in login_session:
        return redirect('/login')
    '''on form submit, saving the fields to the database,
    flashing a message to the user and redirecting to the main screen'''
    if request.method == 'POST':
        newWardrobe = Wardrobe(name=request.form['name'], user_id=login_session['user_id'])
        session.add(newWardrobe)
        session.commit()
        flash("%s Added!" % newWardrobe.name)
        return redirect(url_for('showWardrobes'))
    else:
        return render_template('newwardrobe.html')

@app.route('/wardrobe/<int:wardrobe_id>/edit/', methods=['GET', 'POST'])
def editWardrobe(wardrobe_id):
    if 'username' not in login_session:
        return redirect('/login')
    '''retrieving the item to edit from the database based on the id
    and saving the new information on form submit'''
    editedWardrobe = session.query(
        Wardrobe).filter_by(id=wardrobe_id).one()
    if login_session['user_id'] != editedWardrobe.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit this wardrobe.');}</script><body onload='myFunction()''>"
        return redirect(url_for('showWardrobes'))
    if request.method == 'POST':
        if request.form['name']:
            editedWardrobe.name = request.form['name']
        session.add(editedWardrobe)
        session.commit()
        flash("Your Wardrobe was Edited Successfully")
        return redirect(url_for('showWardrobes'))
    else:
        return render_template(
            'editwardrobe.html', wardrobe=editedWardrobe)

@app.route('/wardrobe/<int:wardrobe_id>/delete/', methods=['GET', 'POST'])
def deleteWardrobe(wardrobe_id):
    if 'username' not in login_session:
        return redirect('/login')
    # retrieving the item to delete and deleting upon confirmation
    wardrobeToDelete = session.query(
            Wardrobe).filter_by(id=wardrobe_id).one()
    if login_session['user_id'] != wardrobeToDelete.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete this wardrobe. You can only delete your own wardrobe.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(wardrobeToDelete)
        session.commit()
        flash("%s Deleted Successfully" % wardrobeToDelete.name)
        return redirect(url_for('showWardrobes'))
    else:
        return render_template('deletewardrobe.html', wardrobe = wardrobeToDelete)

@app.route('/wardrobe/<int:wardrobe_id>/')
@app.route('/wardrobe/<int:wardrobe_id>/clothing/')
def showClothing(wardrobe_id):
    # retrieving and displaying items based on the id
    wardrobe = session.query(Wardrobe).filter_by(id=wardrobe_id).one()
    creator = getUserInfo(wardrobe.user_id)
    clothing = session.query(Clothing).filter_by(
        wardrobe_id=wardrobe_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicclothing.html', clothing=clothing, wardrobe=wardrobe, creator=creator)
    return render_template('clothing.html', wardrobe = wardrobe, clothing = clothing, creator=creator)

@app.route('/wardrobe/<int:wardrobe_id>/clothing/new', methods=['GET', 'POST'])
def newClothing(wardrobe_id):
    if 'username' not in login_session:
        return redirect('/login')
    # choosing the correct wardrobe and saving new items on form submit
    wardrobe = session.query(Wardrobe).filter_by(id=wardrobe_id).one()
    if login_session['user_id'] != wardrobe.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add new clothing to this wardrobe. Please create your own wardrobe to add clothing.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = Clothing(
            name = request.form['name'], description=request.form['description'],
            function=request.form['function'], wardrobe_id=wardrobe_id,
            user_id = login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("New Clothing Added Successfully")
        return redirect(url_for('showClothing', wardrobe_id=wardrobe_id))
    else:
        return render_template('newclothing.html', wardrobe_id=wardrobe_id)

@app.route('/wardrobe/<int:wardrobe_id>/clothing/<int:clothing_id>/edit', methods=['GET', 'POST'])
def editClothing(wardrobe_id, clothing_id):
    if 'username' not in login_session:
        return redirect('/login')
    # retrieving the item to be edited and changing the appropriate field on form submit
    editedItem = session.query(Clothing).filter_by(id=clothing_id).one()
    if login_session['user_id'] != editedItem.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit clothes from this wardrobe.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['function']:
            editedItem.course = request.form['function']
        session.add(editedItem)
        session.commit()
        flash("Clothing Edited Successfully")
        return redirect(url_for('showClothing', wardrobe_id=wardrobe_id))
    else:
        return render_template('editclothing.html', wardrobe_id=wardrobe_id, clothing_id=clothing_id, item = editedItem)

@app.route('/wardrobe/<int:wardrobe_id>/clothing/<int:clothing_id>/delete', methods=['GET', 'POST'])
def deleteClothing(wardrobe_id, clothing_id):
    if 'username' not in login_session:
        return redirect('/login')
    # querying the database to select the item to delete and doing so after confirmation
    wardrobe = session.query(Wardrobe).filter_by(id=wardrobe_id).one()
    itemToDelete = session.query(Clothing).filter_by(id=clothing_id).one()
    if login_session['user_id'] != wardrobe.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete clothing from this wardrobe.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Clothing Successfully Deleted")
        return redirect(url_for('showClothing', wardrobe_id=wardrobe_id))
    else:
        return render_template('deleteclothing.html', item=itemToDelete)

# these functions display JSON data
@app.route('/wardrobe/JSON')
def wardrobeJSON():
    wardrobes = session.query(Wardrobe).all()
    return jsonify(Wardrobes=[w.serialize for w in wardrobes])

@app.route('/wardrobe/<int:wardrobe_id>/clothing/JSON')
def wardrobeClothingJSON(wardrobe_id):
    wardrobe = session.query(Wardrobe).filter_by(id=wardrobe_id).one()
    items= session.query(Clothing).filter_by(
        wardrobe_id=wardrobe_id).all()
    return jsonify(Clothing=[i.serialize for i in items])

@app.route('/wardrobe/<int:wardrobe_id>/clothing/<int:clothing_id>/JSON')
def clothingJSON(wardrobe_id, clothing_id):
    clothing = session.query(Clothing).filter_by(id=clothing_id).one()
    return jsonify(Clothing=clothing.serialize)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)
