import json
from apiclient.discovery import build_from_document, build
import httplib2
import random
import time

from oauth2client.client import OAuth2WebServerFlow, AccessTokenCredentials
from flask import Flask, render_template, session, request, redirect, url_for, abort, jsonify, Response
from flask_socketio import SocketIO, emit, join_room, leave_room

from keys import CLIENT_ID, CLIENT_SECRET
from threading import Thread
from flask_pymongo import PyMongo


app = Flask(__name__)
app.secret_key = 'mysecretKEY'
socketio = SocketIO(app)
mongo = PyMongo(app)


activeRooms = {}

def getComments(id, youtube, credentials, pageToken=""):

  print("GETTING with token {}".format(pageToken))
  if id not in activeRooms or len(activeRooms[id]) == 0:
    print("NO USERS")
    activeRooms.pop(id, None)
    return

  if not any(c.access_token == credentials.access_token for c in activeRooms[id]):
    print("USING SOMEONE ELSES CREDS")
    credentials = activeRooms[id][0]
    http = httplib2.Http()
    http = credentials.authorize(http)
    youtube = build("youtube", "v3", http=http)

  liveStreamingInfo = youtube.videos().list(
    part="liveStreamingDetails",
    id=id
  ).execute()
  try:
    liveStreamingInfo = liveStreamingInfo['items'][0]['liveStreamingDetails']['activeLiveChatId']
  except:
    print("no livestreaming info")

  comments = youtube.liveChatMessages().list(
    liveChatId=liveStreamingInfo,
    part="snippet, authorDetails",
    pageToken=pageToken
  ).execute()
  # insert comments['items'] into mongodb, only want author, display text, and current room id
  with app.app_context():
    if len(comments['items']):
      mongo.db.comments.insert_many(
        [{'text': comment['snippet']['displayMessage'], 'author': comment['authorDetails']['displayName'], 'publishedAt': comment['snippet']['publishedAt'], "channel": id} for comment in comments['items']])
  comments['items'] = list(reversed(comments['items']))


  print("EMITTING TO ROOM {}".format(id))
  socketio.emit('comments', comments, room=id)
  socketio.sleep(0)
  print("WAITING {}".format(comments['pollingIntervalMillis']/1000.0))
  time.sleep(comments["pollingIntervalMillis"]/1000.0)
  getComments(id, youtube, credentials, comments["nextPageToken"])


@socketio.on('connect')
def test_connect():
  print('Client connected')

@socketio.on('disconnect')
def test_disconnect():
    global activeRooms
    print('Client disconnected')
    credentials = AccessTokenCredentials(session['credentials'], 'user-agent-value')
    for room in activeRooms:
      for c in activeRooms[room]:
        if c.access_token == credentials.access_token:
          print("FOUND AND REMOVING")
          activeRooms[room].remove(c)


@socketio.on('join')
def on_join(data):
  print("joining")
  #  On join of a room. Check if that room is currently an active room.
  #  If its not, add it to the active rooms and start getting comments for it.
  #  If it is, do nothing
  id = data['id']
  join_room(id)
  credentials = AccessTokenCredentials(session['credentials'], 'user-agent-value')
  global activeRooms
  if id not in activeRooms:
    activeRooms[id] = [credentials]

    http = httplib2.Http()
    http = credentials.authorize(http)

    youtube = build("youtube", "v3", http=http)
    thread1 = Thread(target=getComments, args = (id, youtube, credentials))
    thread1.start()
  else:
    activeRooms[id].append(credentials)

@app.route('/comments/<username>')
def getCommentCountForUser(username):
  try:
    print(username)
    commentsCount = mongo.db.comments.count({"author": username})
    return jsonify({'comments': commentsCount})
  except Exception as e:
    print(e)


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

  topVid = None
  try:
    youtube = build("youtube", "v3", http=http)
    topVid = youtube.search().list(
      part="snippet",
      eventType="live",
      type="video",
      videoEmbeddable="true"
    ).execute()
  except Exception as e:
    return redirect(url_for('login'))
    
  topVid = topVid['items'][0]

  return render_template("index.html", topVid=json.dumps(topVid))

if __name__ == '__main__':
  app.run(host='0.0.0.0')
  socketio.run(app)
