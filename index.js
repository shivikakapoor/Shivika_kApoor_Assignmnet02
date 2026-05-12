require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

const mongoUri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`;

let userCollection;

async function connectDB() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  const db = client.db(process.env.MONGODB_DATABASE);
  userCollection = db.collection('users');
  console.log('Connected to MongoDB');
}
connectDB();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: mongoUri,
    dbName: process.env.MONGODB_DATABASE,
    collectionName: 'sessions'
  }),
  cookie: { maxAge: 60 * 60 * 1000 }
}));

// Middleware
function sessionValidation(req, res, next) {
  if (req.session.authenticated) {
    next();
  } else {
    res.redirect('/login');
  }
}

function adminAuthorization(req, res, next) {
  if (req.session.user_type !== 'admin') {
    res.status(403).render('403');
  } else {
    next();
  }
}

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user || null });
});

// Signup GET
app.get('/signup', (req, res) => {
  res.render('signup');
});

// Signup POST
app.post('/signupSubmit', async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required()
  });

  const { error } = schema.validate({ name, email, password });
  if (error) {
    return res.render('signup', { error: error.details[0].message });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword, user_type: 'user' });
  req.session.authenticated = true;
  req.session.user_type = 'user';
  req.session.user = { name, email, user_type: 'user' };
  res.redirect('/members');
});

// Login GET
app.get('/login', (req, res) => {
  res.render('login');
});

// Login POST
app.post('/loginSubmit', async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(50).required()
  });

  const { error } = schema.validate({ email, password });
  if (error) {
    return res.render('login', { error: 'Invalid email or password.' });
  }

  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.render('login', { error: 'Invalid email/password combination.' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.render('login', { error: 'Invalid email/password combination.' });
  }

  req.session.authenticated = true;
  req.session.user_type = user.user_type;
  req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
  res.redirect('/members');
});

// Members
app.get('/members', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.render('members', { user: req.session.user });
});

// Admin
app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
  const users = await userCollection.find().toArray();
  res.render('admin', { users });
});

// Promote user to admin
app.get('/promoteUser', async (req, res) => {
  const schema = Joi.string().max(50).required();
  const { error } = schema.validate(req.query.name);
  if (error) return res.redirect('/admin');

  await userCollection.updateOne({ name: req.query.name }, { $set: { user_type: 'admin' } });
  res.redirect('/admin');
});

// Demote user to regular
app.get('/demoteUser', async (req, res) => {
  const schema = Joi.string().max(50).required();
  const { error } = schema.validate(req.query.name);
  if (error) return res.redirect('/admin');

  await userCollection.updateOne({ name: req.query.name }, { $set: { user_type: 'user' } });
  res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 404
app.get('*splat', (req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));