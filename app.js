const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const session = require('express-session');

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');

const rutaMensaje1 = require('./routes/mensajes1');
const rutaMensaje2 = require('./routes/mensajes2');
const auth2Router = require('./routes/auth2');
const connectDB2 = require('./db2');
connectDB2();
const app = express();

// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// Middlewares
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'secreto-app2',
  resave: false,
  saveUninitialized: false
}));

// Rutas
app.use('/', indexRouter);
app.use('/users', usersRouter);

app.use('/message1', rutaMensaje1);
app.use('/message2', rutaMensaje2);
app.use('/auth2', auth2Router);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;