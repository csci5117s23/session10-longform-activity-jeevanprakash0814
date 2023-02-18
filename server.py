from flask import *

import json

import os
from os import environ as env

from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
# from dotenv import find_dotenv, load_dotenv

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# AUTH

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token # session is from flask
    state = session.get("user")

    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("info", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

# CONTENT

@app.route("/")
def info():
    logout_state = ""
    state = "temp"
    if session.get("user") is None:
        logout_state = "login"
    else:
        logout_state = "logout"
        state = json.dumps(session.get("user"),indent=4)

    return render_template('main.html',logout_state=logout_state,state=state)