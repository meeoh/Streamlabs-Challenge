import json
from apiclient.discovery import build_from_document, build
import httplib2
import random

from oauth2client.client import OAuth2WebServerFlow, AccessTokenCredentials

from flask import Flask, render_template, session, request, redirect, url_for, abort, jsonify
from flask_socketio import SocketIO, emit, send

CLIENT_ID = "759997836419-uovn15kki2cshhlc23fdpe9njq1h589k.apps.googleusercontent.com"
CLIENT_SECRET = 'u5K2AVqwyPQ3pZhFdtlQEjIr'

app = Flask(__name__)
socketio = SocketIO(app)

@socketio.on('connect')
def test_connect():
  print('connect')
  emit('connect')

@app.route('/login')
def login():
  flow = OAuth2WebServerFlow(client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    scope='https://www.googleapis.com/auth/youtube',
    redirect_uri='http://localhost:5000/oauth2callback',
    approval_prompt='force',
    access_type='offline')

  auth_uri = flow.step1_get_authorize_url()
  return redirect(auth_uri)

@app.route('/signout')
def signout():
  del session['credentials']
  session['message'] = "You have logged out"

  return redirect(url_for('index'))

@app.route('/oauth2callback')
def oauth2callback():
  code = request.args.get('code')
  if code:
    # exchange the authorization code for user credentials
    flow = OAuth2WebServerFlow(CLIENT_ID,
      CLIENT_SECRET,
      "https://www.googleapis.com/auth/youtube")
    flow.redirect_uri = request.base_url
    try:
      credentials = flow.step2_exchange(code)
    except Exception as e:
      print "Unable to get an access token because ", e.message

    # store these credentials for the current user in the session
    # This stores them in a cookie, which is insecure. Update this
    # with something better if you deploy to production land
    session['credentials'] = credentials.access_token

  return redirect(url_for('index'))

@app.route('/')
def index():
  if 'credentials' not in session:
    return redirect(url_for('login'))

  credentials = AccessTokenCredentials(session['credentials'], 'user-agent-value')

  http = httplib2.Http()
  http = credentials.authorize(http)

  youtube = build("youtube", "v3", http=http)
  topVid = youtube.search().list(
    part="snippet",
    eventType="live",
    type="video",
    videoEmbeddable="true"
  ).execute()

  topVid = topVid['items'][0]
  id = topVid['id']['videoId']

  liveStreamingInfo = youtube.videos().list(
    part="liveStreamingDetails",
    id=id
  ).execute()
  # try:
  #   liveStreamingInfo = liveStreamingInfo['items'][0]['liveStreamingDetails']['activeLiveChatId']
  # except:
  #   print("no livestreaming info")

  # comments = youtube.liveChatMessages().list(
  #   liveChatId=liveStreamingInfo,
  #   part="snippet, authorDetails"
  # ).execute()

  # print(comments['items'][0]['authorDetails'])

  return render_template("index.html", topVid=json.dumps(topVid))

if __name__ == '__main__':
  app.secret_key = 'hello world'
  app.run(host='0.0.0.0')
  socketio.run(app)