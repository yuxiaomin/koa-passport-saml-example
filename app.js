'use strict';

const Koa = require('koa');
const koaPassport = require('./passport');
const Router = require('koa-router');
const session = require('koa-generic-session');
const koaBody = require('koa-body');


const app = new Koa();

const cookieKey = 'my-cookie-name-prefix';

// passpport
app.use(koaPassport.initialize());

// sessions
app.keys = ['your-session-secret'];
app.use(session({
  key: cookieKey,
  cookie: {
      path: '/',
      httpOnly: true,
      maxAge: 30 * 60 * 1000, // 30 mins
      overwrite: true,
      signed: true
  }
}));
app.use(koaPassport.session());

// body parser
app.use(koaBody());

// authMiddleware
const authMiddleware = async (ctx, next) => {
  console.log('validating auth');
  if (ctx.isAuthenticated()) {
    return next();
  } else {
    console.log('redirecting for SAML login');
    ctx.redirect('/auth/login');
  }
};

// auth Routes
const authRouter = new Router();
authRouter.get('/auth/login', koaPassport.authenticate('saml'));
authRouter.post('/auth/saml/callback', koaPassport.authenticate('saml'), ctx => ctx.redirect('/'));

authRouter.post('/auth/saml/logout/callback', koaPassport.logoutSamlCallback);

authRouter.post('/auth/logout', async (ctx, next) => {
    console.log('[app.js] Receive the /auth/logout request, start to destroy session and delete cookie');
    ctx.session = null;
    ctx.cookies.set(cookieKey, null);
    ctx.cookies.set(`${cookieKey}.sig`, null);
    await next();
  },
  koaPassport.authenticate('saml'), 
  async (ctx, next) => {
      console.log('[app.js] Finish the logout and start to redirect');
      ctx.redirect('/');
  });

// other routes - these require authentication!
const router = new Router();
router.use(authMiddleware);

router.get('/', function(ctx) {
  ctx.body = 'You\'re authenticated!';
});

app.use(authRouter.routes());
app.use(router.routes());

// start server
const port = process.env.PORT || 8080;
app.listen(port, () => console.log('Server listening on', port));
