'use strict'; // https://www.w3schools.com/js/js_strict.asp

const serverDomain = 'peaceful-hollows-08391.herokuapp.com';

require('dotenv').config();

const { Server } = require('socket.io');
const http = require('http');
const https = require('https');
const compression = require('compression');
const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

const session = require('express-session');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const bodyParser = require("body-parser");

app.use(cors()); // Enable All CORS Requests for all origins
app.use(compression()); // Compress all HTTP responses using GZip

const isHttps = false; // must be the same to client.js isHttps
const port = process.env.PORT || 3000; // must be the same to client.js signalingServerPort

let io, server, host;

if (isHttps) {
    const fs = require('fs');
    const options = {
        key: fs.readFileSync(path.join(__dirname, '../ssl/key.pem'), 'utf-8'),
        cert: fs.readFileSync(path.join(__dirname, '../ssl/cert.pem'), 'utf-8'),
    };
    server = https.createServer(options, app);
    io = new Server().listen(server);
    host = 'https://' + serverDomain + ':' + port;
} else {
    server = http.createServer(app);
    io = new Server().listen(server);
    host = 'http://' + serverDomain + ':' + port;
}

const ngrok = require('ngrok');
const ngrokEnabled = process.env.NGROK_ENABLED;
const ngrokAuthToken = process.env.NGROK_AUTH_TOKEN;
const turnEnabled = process.env.TURN_ENABLED;
const turnUrls = process.env.TURN_URLS;
const turnUsername = process.env.TURN_USERNAME;
const turnCredential = process.env.TURN_PASSWORD;

const Logger = require('./Logger');
const log = new Logger('server');

let channels = {}; // collect channels
let sockets = {}; // collect sockets
let peers = {}; // collect peers info grp by channels

// Use all static files from the public folder
app.use(express.static(path.join(__dirname, '../../', 'public')));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

// Api parse body data as json
app.use(express.json());

// Use these before mongoose.connect
// Use Session Package
const sessionMiddleware = session({ 
    secret: process.env.SECRET,
    resave: false, 
    saveUninitialized: false 
});
app.use(sessionMiddleware);

// Initialize Passport 
app.use(passport.initialize());
// Make/ Allow Passport Use Session
app.use(passport.session());

// Connect MongoDB
const connectURI = "mongodb+srv://" + process.env.DB_USER + ":" + process.env.DB_PASS + "@cluster0.macis.mongodb.net/" + process.env.DB_NAME + "?retryWrites=true&w=majority"
mongoose.connect(connectURI)

//Create a schema
const userSchema = new mongoose.Schema({
    userid: String,
    name: String,
    email: String,
    picture: String,
    isguest: {
        type: Boolean,
        default: false
    }
});

//Create a schema
const meetingSchema = new mongoose.Schema({
    meetid: String,
    hostid: String,
    invites: [String],
    status: {
        type: Boolean,
        default: false
    }
});

// Adding plugin to userSchema for findOrCreate OAuth20
userSchema.plugin(findOrCreate);

const User = mongoose.model('User', userSchema);
const Meeting = mongoose.model('Meeting', meetingSchema);

function getMeeting(mID, done) {
    Meeting.findOne({meetid: mID}, (err, meeting) => {
        if (err) return done(err, null);
        if (meeting) return done(null, meeting);
        return done(null, null);
    });
}

function isValidMeeting(meeting, email) {
    if (!meeting) return false;
    const invites = meeting.invites;
    if (invites.includes(email)) return true;
    return false;
}

function isGuestUser(email) {
    const emailDomain = email.substring(email.lastIndexOf("@") + 1);
    const DOMAIN = "iitjammu.ac.in";
    return emailDomain.localeCompare(DOMAIN) != 0;
}

function isValidHost(meeting, uID) {
    if (!meeting) return false;
    return uID.localeCompare(meeting.hostid) == 0;
}

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    userProfileURL: process.env.GOOGLE_PROFILE_URL
    },
    (accessToken, refreshToken, profile, done) => {
        const GUEST = isGuestUser(profile._json.email);
        const USER = {
            userid: profile.id,
            name: profile._json.name,
            email: profile._json.email,
            picture: profile._json.picture,
            isguest: GUEST
        }
        User.findOrCreate({userid: profile.id}, USER, (err, user) => {
            return done(err, user);
        });
    }
));

// Serialize User for Every Strategy
// NOTE: user.id => id assigned by mongoDB to user in DB
passport.serializeUser((user, done) => {
    done(null, user.id);
});
  
// DeSerialize User for Every Strategy
passport.deserializeUser((id, done) => {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] 
}));

// callback URI
app.get('/auth/google/callback', passport.authenticate('google', {
    successRedirect: '/dashboard',
    failureRedirect: '/'
}));

/* 
GET: /home
if isAuth(req) => redirect to '/dashboard' else render 'home' page
*/
app.get('/', (req, res) => {
    if (req.isAuthenticated())
        return res.redirect('/dashboard');
    res.render('home');
});

/* 
GET: /dashboard
if isAuth(req) => render 'dashboard' page else redirect to '/'
with some popup/ flash msg/ alert to login first
*/
app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        const PIC = req.user.picture ? req.user.picture : "../images/avatar2.png";
        const PARAMS = {
            name: req.user.name,
            email: req.user.email,
            picture: PIC,
            isguest: req.user.isguest
        }
        return res.render('dash', PARAMS);
    }
    res.redirect('/');
});

/* 
GET: /join 
if isAuth(req) => render 'join' page else redirect to '/'
with some popup/ flash msg/ alert to login first
*/
app.get('/join', (req, res) => {
    if (req.isAuthenticated()) {
        const PIC = req.user.picture ? req.user.picture : "../images/avatar2.png";
        const PARAMS = {
            name: req.user.name,
            email: req.user.email,
            picture: PIC,
            modal: null
        }
        return res.render('join', PARAMS);
    }
    res.redirect('/');
});

/* 
GET: /join/:mid
if isAuth(req) => if isValid(mid) => if isInvited(user, mid)
=> if isStarted(mid) => render 'meet' page else check if 
isHost(user, mid) => redirect to '/host/mid' else render 'meet'
with 'waiting for host to start meeting' OR 'meeting isn't
scheduled today' / etc. message (design choice) else redirect
to '/join' with some popup/ flash msg/ alert to enter correct mid
as user isn't invited to meet OR mid isn't valid else
redirect to '/' with some popup/ flash msg/ alert to login first
*/
app.get('/join/:mid', (req, res) => {
    if (!req.isAuthenticated()) 
        return res.redirect('/');
    const mID = req.params.mid;
    getMeeting(mID, (err, meeting) => {
        const PIC = req.user.picture ? req.user.picture : "../images/avatar2.png";
        let PARAMS = {
            name: req.user.name,
            email: req.user.email,
            picture: PIC,
            modal: {content: '', msg: ''}
        }
        let MODAL = null;
        if (err || !meeting) {
            if (err) console.log(err);
            PARAMS.modal.content =  err ? "An error occured!" : "Invalid Meeting ID!";
            PARAMS.modal.msg = err ? "Refresh and Enter Meeting ID Again" : "Meeting ID: " + mID + " doesn't exist";
            res.render('join', PARAMS);
            return console.log(PARAMS.modal);
        }
        const isValid = isValidMeeting(meeting, req.user.email);
        if (!isValid || !meeting.status) {
            PARAMS.modal.content = "Sorry, " + (!isValid ? "You're not invited!" : "Meeting has not started yet!");
            PARAMS.modal.msg = !isValid ? "Ask" : "Waiting for";
            PARAMS.modal.msg += " Host of Meeting ID: " + mID + " to " + (!isValid ? "invite you" :  "start the Meeting");
            res.render('join', PARAMS);
            return console.log(PARAMS.modal);
        }
        res.render('client');
    });
});

/* 
GET: /host
if isAuth(req) => if (!isguest) => render 'host' page else redirect
=> to '/dashboard' with some popup/ flash msg/ alert else redirect
to '/' with some popup/ flash msg/ alert to login first
*/
app.get('/host', (req, res) => {
    if (req.isAuthenticated()) {
        if (!req.user.isguest) {
            const PIC = req.user.picture ? req.user.picture : "../images/avatar2.png";
            const PARAMS = {
                name: req.user.name,
                email: req.user.email,
                picture: PIC
            }
            return res.render('host', PARAMS);
        }
        return res.redirect('/dashboard');
    }
    res.redirect('/');
});

/* 
GET: /host/:mid
if isAuth(req) => if (!isguest) => render 'host' page else redirect
=> to '/dashboard' with some popup/ flash msg/ alert else redirect
to '/' with some popup/ flash msg/ alert to login first
*/
app.get('/host/:mid', (req, res) => {
    if (!req.isAuthenticated() || req.user.isguest) 
        return res.redirect('/');
    const mID = req.params.mid;
    getMeeting(mID, (err, meeting) => {
        if (err) {
            console.log(err);
            res.redirect('/host');
            const msg =  "Try Again! An error occured";
            return console.log(msg);
        }
        if (meeting && !isValidHost(meeting, req.user.userid)) {
            const msg = "Sorry! You're not host";
            res.redirect('/join');
            return console.log(msg);
        }
        if (!meeting) {
            console.log(mID + ": Meeting not found so starting it");
            const MEET = {
                meetid: mID,
                hostid: req.user.userid,
                invites: [req.user.email],
                status: true,
            };
            const meet = new Meeting(MEET);
            meet.save((err) => {
                if (err) console.log(err);
            });
            console.log(mID + ": Meeting added to DB and started!");
        }
        else {
            Meeting.findByIdAndUpdate(meeting.id, {status: true}, (err, res) => {
                if (err) console.log(err);
                console.log(res);
            });
            console.log(mID + ": Meeting already exist and started!");
        }
        return res.render('client');
    });
});

/* 
GET: /login route
if isAuth(req) => redirect to '/dashboard' with some popup/ flash msg/ alert
else redirect to '/auth/google'
*/
app.get('/login', (req, res) => {
    if (req.isAuthenticated())
        return res.redirect('/dashboard');
    res.redirect('/auth/google');
});

/* 
GET: /logout route
if isAuth(req) => logout user else popup/ flash msg/ alert
finally redirect to '\'
*/
app.get('/logout', (req, res) => {
    if (req.isAuthenticated())
        req.logout();
    res.redirect('/');
});

// no room name specified to join
app.get('/join/', (req, res) => {
    res.redirect('/');
});

app.get('/api/user', (req, res) => {
    return req.isAuthenticated() ? res.json(req.user) : res.json({});
});

// this is default in case of unmatched routes
app.use((req, res) => {
    // Invalid request
    res.json({
    error: {
        'name':'Error',
        'status':404,
        'message':'Invalid Request, No route is Matched!',
        'statusCode':404,
        'stack':host
    },
        message: 'Testing!'
    });
});

/**
 * You should probably use a different stun-turn server
 * doing commercial stuff, also see:
 *
 * https://gist.github.com/zziuni/3741933
 * https://www.twilio.com/docs/stun-turn
 * https://github.com/coturn/coturn
 *
 * Check the functionality of STUN/TURN servers:
 * https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/
 */
const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];

if (turnEnabled == 'true') {
    iceServers.push({
        urls: turnUrls,
        username: turnUsername,
        credential: turnCredential,
    });
}

/**
 * Expose server to external with https tunnel using ngrok
 * https://ngrok.com
 */
async function ngrokStart() {
    try {
        await ngrok.authtoken(ngrokAuthToken);
        await ngrok.connect(port);
        let api = ngrok.getApi();
        let data = await api.listTunnels();
        let pu0 = data.tunnels[0].public_url;
        let pu1 = data.tunnels[1].public_url;
        let tunnelHttps = pu0.startsWith('https') ? pu0 : pu1;
        // server settings
        log.debug('settings', {
            server: host,
            server_tunnel: tunnelHttps,
            api_docs: api_docs,
            api_key_secret: api_key_secret,
            iceServers: iceServers,
            ngrok: {
                ngrok_enabled: ngrokEnabled,
                ngrok_token: ngrokAuthToken,
            },
        });
    } catch (err) {
        console.error('[Error] ngrokStart', err);
        process.exit(1);
    }
}

/**
 * Start Local Server with ngrok https tunnel (optional)
 */
server.listen(port, null, () => {
    console.log('Server started listening at port:', port);
    // https tunnel
    if (ngrokEnabled == 'true')
        ngrokStart();
});

// convert a connect middleware to a Socket.IO middleware
const wrap = middleware => (socket, next) => middleware(socket.request, {}, next);

io.use(wrap(sessionMiddleware));
io.use(wrap(passport.initialize()));
io.use(wrap(passport.session()));

io.use((socket, next) => {
    if (socket.request.user) {
        next();
    } else {
        next(new Error('unauthorized'))
    }
});

/**
 * Users will connect to the signaling server, after which they'll issue a "join"
 * to join a particular channel. The signaling server keeps track of all sockets
 * who are in a channel, and on join will send out 'addPeer' events to each pair
 * of users in a channel. When clients receive the 'addPeer' event they'll begin
 * setting up an RTCPeerConnection with one another. During this process they'll
 * need to relay ICECandidate information to one another, as well as SessionDescription
 * information. After all of that happens, they'll finally be able to complete
 * the peer connection and will be in streaming audio/video between eachother.
 * On peer connected
 */
io.sockets.on('connect', (socket) => {
    const user = socket.request.user;
    log.debug('[' + socket.id + '] connection accepted');

    socket.channels = {};
    sockets[socket.id] = socket;

    /**
     * On peer diconnected
     */
    socket.on('disconnect', () => {
        for (let channel in socket.channels) {
            removePeerFrom(channel);
        }
        log.debug('[' + socket.id + '] disconnected');
        delete sockets[socket.id];
    });

    /**
     * On peer join
     */
    socket.on('join', (config) => {
        log.debug('[' + socket.id + '] join ', config);

        let channel = config.channel;
        // config.peer_name = user.name;
        let peer_name = config.peer_name;
        let peer_video = config.peer_video;
        let peer_audio = config.peer_audio;
        let peer_hand = config.peer_hand;
        let peer_rec = config.peer_rec;
        let peer_pic = config.peer_pic;

        if (channel in socket.channels) {
            log.debug('[' + socket.id + '] [Warning] already joined', channel);
            return;
        }
        // no channel aka room in channels init
        if (!(channel in channels)) channels[channel] = {};

        // no channel aka room in peers init
        if (!(channel in peers)) peers[channel] = {};

        // room locked by the participants can't join
        if (peers[channel]['Locked'] === true) {
            log.debug('[' + socket.id + '] [Warning] Room Is Locked', channel);
            socket.emit('roomIsLocked');
            return;
        }

        // collect peers info grp by channels
        peers[channel][socket.id] = {
            peer_name: peer_name,
            peer_video: peer_video,
            peer_audio: peer_audio,
            peer_hand: peer_hand,
            peer_rec: peer_rec,
            peer_pic: peer_pic
        };
        log.debug('connected peers grp by roomId', peers);

        addPeerTo(channel);

        channels[channel][socket.id] = socket;
        socket.channels[channel] = channel;
    });

    /**
     * Add peers to channel aka room
     * @param {*} channel
     */
    async function addPeerTo(channel) {
        for (let id in channels[channel]) {
            // offer false
            await channels[channel][id].emit('addPeer', {
                peer_id: socket.id,
                peers: peers[channel],
                should_create_offer: false,
                iceServers: iceServers,
            });
            // offer true
            socket.emit('addPeer', {
                peer_id: id,
                peers: peers[channel],
                should_create_offer: true,
                iceServers: iceServers,
            });
            log.debug('[' + socket.id + '] emit addPeer [' + id + ']');
        }
    }

    /**
     * Remove peers from channel aka room
     * @param {*} channel
     */
    async function removePeerFrom(channel) {
        if (!(channel in socket.channels)) {
            log.debug('[' + socket.id + '] [Warning] not in ', channel);
            return;
        }

        delete socket.channels[channel];
        delete channels[channel][socket.id];
        delete peers[channel][socket.id];

        switch (Object.keys(peers[channel]).length) {
            case 0:
                // last peer disconnected from the room without room status set, delete room data
                delete peers[channel];
                break;
            case 1:
                // last peer disconnected from the room having room status set, delete room data
                if ('Locked' in peers[channel]) delete peers[channel];
                break;
        }

        for (let id in channels[channel]) {
            await channels[channel][id].emit('removePeer', { peer_id: socket.id });
            socket.emit('removePeer', { peer_id: id });
            log.debug('[' + socket.id + '] emit removePeer [' + id + ']');
        }
    }

    /**
     * Relay ICE to peers
     */
    socket.on('relayICE', (config) => {
        let peer_id = config.peer_id;
        let ice_candidate = config.ice_candidate;

        // log.debug('[' + socket.id + '] relay ICE-candidate to [' + peer_id + '] ', {
        //     address: config.ice_candidate,
        // });

        sendToPeer(peer_id, sockets, 'iceCandidate', {
            peer_id: socket.id,
            ice_candidate: ice_candidate,
        });
    });

    /**
     * Relay SDP to peers
     */
    socket.on('relaySDP', (config) => {
        let peer_id = config.peer_id;
        let session_description = config.session_description;

        log.debug('[' + socket.id + '] relay SessionDescription to [' + peer_id + '] ', {
            type: session_description.type,
        });

        sendToPeer(peer_id, sockets, 'sessionDescription', {
            peer_id: socket.id,
            session_description: session_description,
        });
    });

    /**
     * Refresh Room Status (Locked/Unlocked)
     */
    socket.on('roomStatus', (config) => {
        let room_id = config.room_id;
        let room_locked = config.room_locked;
        // config.peer_name = user.name;
        let peer_name = config.peer_name;

        peers[room_id]['Locked'] = room_locked;

        log.debug('[' + socket.id + '] emit roomStatus' + ' to [room_id: ' + room_id + ' locked: ' + room_locked + ']');

        sendToRoom(room_id, socket.id, 'roomStatus', {
            peer_name: peer_name,
            room_locked: room_locked,
        });
    });

    // /**
    //  * Relay NAME to peers
    //  */
    socket.on('peerName', (config) => {
        let room_id = config.room_id;
        config.peer_name_old = user.name;
        let peer_name_old = config.peer_name_old;
        config.peer_name_new = user.name;
        let peer_name_new = config.peer_name_new;
        let peer_id_to_update = null;

        for (let peer_id in peers[room_id]) {
            if (peer_id == 'Locked') continue;
            if (peers[room_id][peer_id]['peer_name'] == peer_name_old) {
                peers[room_id][peer_id]['peer_name'] = peer_name_new;
                peer_id_to_update = peer_id;
            }
        }

        if (peer_id_to_update) {
            log.debug('[' + socket.id + '] emit peerName to [room_id: ' + room_id + ']', {
                peer_id: peer_id_to_update,
                peer_name: peer_name_new,
            });

            sendToRoom(room_id, socket.id, 'peerName', {
                peer_id: peer_id_to_update,
                peer_name: peer_name_new,
            });
        }
    });

    /**
     * Relay Audio Video Hand ... Status to peers
     */
    socket.on('peerStatus', (config) => {
        let room_id = config.room_id;
        // config.peer_name = user.name;
        let peer_name = config.peer_name;
        let element = config.element;
        let status = config.status;

        for (let peer_id in peers[room_id]) {
            if (peer_id == 'Locked') continue;
            if (peers[room_id][peer_id]['peer_name'] == peer_name) {
                switch (element) {
                    case 'video':
                        peers[room_id][peer_id]['peer_video'] = status;
                        break;
                    case 'audio':
                        peers[room_id][peer_id]['peer_audio'] = status;
                        break;
                    case 'hand':
                        peers[room_id][peer_id]['peer_hand'] = status;
                        break;
                    case 'rec':
                        peers[room_id][peer_id]['peer_rec'] = status;
                        break;
                }
            }
        }

        log.debug('[' + socket.id + '] emit peerStatus to [room_id: ' + room_id + ']', {
            peer_id: socket.id,
            element: element,
            status: status,
        });

        sendToRoom(room_id, socket.id, 'peerStatus', {
            peer_id: socket.id,
            peer_name: peer_name,
            element: element,
            status: status,
        });
    });

    /**
     * Relay actions to peers or specific peer in the same room
     */
    socket.on('peerAction', (config) => {
        let room_id = config.room_id;
        // config.peer_name = user.name;
        let peer_name = config.peer_name;
        let peer_action = config.peer_action;
        let peer_id = config.peer_id;

        if (peer_id) {
            log.debug('[' + socket.id + '] emit peerAction to [' + peer_id + '] from room_id [' + room_id + ']');

            sendToPeer(peer_id, sockets, 'peerAction', {
                peer_name: peer_name,
                peer_action: peer_action,
            });
        } else {
            log.debug('[' + socket.id + '] emit peerAction to [room_id: ' + room_id + ']', {
                peer_id: socket.id,
                peer_name: peer_name,
                peer_action: peer_action,
            });

            sendToRoom(room_id, socket.id, 'peerAction', {
                peer_name: peer_name,
                peer_action: peer_action,
            });
        }
    });

    /**
     * Relay Kick out peer from room
     */
    socket.on('kickOut', (config) => {
        let room_id = config.room_id;
        let peer_id = config.peer_id;
        // config.peer_name = user.name;
        let peer_name = config.peer_name;

        log.debug('[' + socket.id + '] kick out peer [' + peer_id + '] from room_id [' + room_id + ']');

        sendToPeer(peer_id, sockets, 'kickOut', {
            peer_name: peer_name,
        });
    });

    /**
     * Relay File info
     */
    socket.on('fileInfo', (config) => {
        let room_id = config.room_id;
        // config.peer_name = user.name;
        let peer_name = config.peer_name;
        let file = config.file;

        function bytesToSize(bytes) {
            let sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            if (bytes == 0) return '0 Byte';
            let i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
            return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
        }

        file['peerName'] = peer_name;

        log.debug('[' + socket.id + '] Peer [' + peer_name + '] send file to room_id [' + room_id + ']', {
            peerName: file.peerName,
            fileName: file.fileName,
            fileSize: bytesToSize(file.fileSize),
            fileType: file.fileType,
        });

        sendToRoom(room_id, socket.id, 'fileInfo', file);
    });

    /**
     * Abort file sharing
     */
    socket.on('fileAbort', (config) => {
        let room_id = config.room_id;
        // config.peer_name = user.name;
        let peer_name = config.peer_name;

        log.debug('[' + socket.id + '] Peer [' + peer_name + '] send fileAbort to room_id [' + room_id + ']');
        sendToRoom(room_id, socket.id, 'fileAbort');
    });

    /**
     * Relay video player action
     */
    socket.on('videoPlayer', (config) => {
        let room_id = config.room_id;
        // config.peer_name = user.name;
        let peer_name = config.peer_name;
        let video_action = config.video_action;
        let video_src = config.video_src;
        let peer_id = config.peer_id;

        let sendConfig = {
            peer_name: peer_name,
            video_action: video_action,
            video_src: video_src,
        };
        let logme = {
            peer_id: socket.id,
            peer_name: peer_name,
            video_action: video_action,
            video_src: video_src,
        };

        if (peer_id) {
            log.debug(
                '[' + socket.id + '] emit videoPlayer to [' + peer_id + '] from room_id [' + room_id + ']',
                logme,
            );

            sendToPeer(peer_id, sockets, 'videoPlayer', sendConfig);
        } else {
            log.debug('[' + socket.id + '] emit videoPlayer to [room_id: ' + room_id + ']', logme);

            sendToRoom(room_id, socket.id, 'videoPlayer', sendConfig);
        }
    });

    /**
     * Whiteboard actions for all user in the same room
     */
    socket.on('wbCanvasToJson', (config) => {
        let room_id = config.room_id;
        // log.debug('Whiteboard send canvas', config);
        sendToRoom(room_id, socket.id, 'wbCanvasToJson', config);
    });

    socket.on('whiteboardAction', (config) => {
        log.debug('Whiteboard', config);
        let room_id = config.room_id;
        sendToRoom(room_id, socket.id, 'whiteboardAction', config);
    });
}); // end [sockets.on-connect]

/**
 * Send async data to all peers in the same room except yourself
 * @param {*} room_id id of the room to send data
 * @param {*} socket_id socket id of peer that send data
 * @param {*} msg message to send to the peers in the same room
 * @param {*} config JSON data to send to the peers in the same room
 */
async function sendToRoom(room_id, socket_id, msg, config = {}) {
    for (let peer_id in channels[room_id]) {
        if (peer_id == 'Locked') continue;
        // not send data to myself
        if (peer_id != socket_id) {
            await channels[room_id][peer_id].emit(msg, config);
        }
    }
}

/**
 * Send async data to specified peer
 * @param {*} peer_id id of the peer to send data
 * @param {*} sockets all peers connections
 * @param {*} msg message to send to the peer in the same room
 * @param {*} config JSON data to send to the peer in the same room
 */
async function sendToPeer(peer_id, sockets, msg, config = {}) {
    if (peer_id in sockets) {
        await sockets[peer_id].emit(msg, config);
    }
}
