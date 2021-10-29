'use strict';

const Strategy = require('passport-saml').Strategy;
const passport = require('koa-passport');
const fs = require('fs');

// Update the variables below with correct values:
const entryPoint = 'my-sso-login-url';  // SSO.saml2
const logoutUrl = 'my-sso-logout-url';  // SLO.saml2
const protocol = 'https:'
const issuer = 'my_issuer_name';
const pathToPublicCert = '/path/to/my.pem';
const pathToPrivateKey = '/path/to/privatekey.pem';
const signatureAlgorithm = 'sha256';

passport.serializeUser(function(user, cb) {
  cb(null, user);
});

passport.deserializeUser(function(user, cb) {
  cb(null, user);
});

function onProfile(profile, cb) {
  return cb(null, 
    (() => {
      const attrs = ['email', 'firstName', 'lastName', 'nameID', 'nameIDFormat', 'sessionIndex'];
      const re = {};
      for(const a of attrs) {
        if (profile[a]) {
          re[a] = profile[a];
        }
      }
      console.log(`[passport] The profile of logged in user is: ${JSON.stringify(re)}`);
      return re;
    })());
}

const samlConf = {
  path: '/auth/saml/callback',
  // set the protocal to https: instead of default http:
  protocol,
  entryPoint,
  logoutUrl,
  issuer,
  cert: fs.readFileSync(pathToPublicCert, 'utf8'),
  privateKey: fs.readFileSync(pathToPrivateKey, 'utf8'),
  // don't pass NameIDPolicy in request
  identifierFormat: null,
  // no forceAuthn in request is the the default behavior
  // forceAuthn: false,
  signatureAlgorithm
};

const samlStrategy = new Strategy(samlConf, onProfile);

const logout = (ctx) => {

  return new Promise((resolve, reject) => {
    samlStrategy.logout(ctx, (err, url) => {
      if (!err) {
        resolve(url);
      } else {
        reject(err);
      }
    })
  })

}

passport.logoutSamlCallback = async (ctx, next) => {
  // const res = ctx.res;
  if (ctx._session && ctx._session.passport && ctx._session.passport.user) {
    ctx.user = {};
    ctx.user.nameID = ctx._session.passport.user.nameID;
    ctx.user.nameIDFormat = ctx._session.passport.user.nameIDFormat;
    ctx.user.sessionIndex = ctx._session.passport.user.sessionIndex;

    
    // session is there, logout
    try {
      const logoutUrl = await logout(ctx);
      console.log(`[passport] The saml logout url is: ${logoutUrl}`);
      ctx.redirect(logoutUrl);
      
    } catch (err) {
      console.warn('[passport] Logout error');
      ctx.redirect('/');
    }
    next();
  } else {
    ctx.redirect('/');
    await next();
  }
  
}

passport.use(samlStrategy);

module.exports = passport;
