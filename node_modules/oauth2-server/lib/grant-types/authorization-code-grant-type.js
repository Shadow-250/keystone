'use strict';

/**
 * Module dependencies.
 */
const jsonwebtoken = require('jsonwebtoken');
var AbstractGrantType = require('./abstract-grant-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidGrantError = require('../errors/invalid-grant-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var ServerError = require('../errors/server-error');
var is = require('../validator/is');
var util = require('util');
var debug = require('debug')('oauth2-server: authorization-code-grant-type');

/**
 * Constructor.
 */

function AuthorizationCodeGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getAuthorizationCode) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getAuthorizationCode()`');
  }

  if (!options.model.revokeAuthorizationCode) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `revokeAuthorizationCode()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(AuthorizationCodeGrantType, AbstractGrantType);

/**
 * Handle authorization code grant.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
 */

AuthorizationCodeGrantType.prototype.handle = function(request, client) {
  if (!request) {
    throw new InvalidArgumentError('Missing parameter: `request`');
  }

  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  return Promise.bind(this)
    .then(function() {
      return this.getAuthorizationCode(request, client);
    })
    .tap(function(code) {
      return this.validateRedirectUri(request, code);
    })
    .tap(function(code) {
      if (!code.valid) {
        return this.revokeTokens(code);
      } else {
        return Promise.resolve(code)
      }
    })
    .tap(function(code) {
      return this.revokeAuthorizationCode(code);
    })
    .then(function(code) {
      return this.saveToken(code.user, client, code.code, code.scope, request);
    }).then(function(data) {
      if (!data.scope.includes('openid')) {
        return data;
      } else {
        return this.idToken(data);
      }
    }).then(function(data) {
      if (!data.scope.includes('openid')) {
        return data;
      } else {
        return this.firmIdToken(data);
      }
    });
};

/**
 * Get the authorization code.
 */

AuthorizationCodeGrantType.prototype.getAuthorizationCode = function(request, client) {
//cambiado para app, donde hay body habia query
  if (!request.body.code) {
    throw new InvalidRequestError('Missing parameter: `code`');
  }

  if (!is.vschar(request.body.code)) {
    throw new InvalidRequestError('Invalid parameter: `code`');
  }
  return promisify(this.model.getAuthorizationCode, 1).call(this.model, request.body.code)
    .then(function(code) {
      if (!code) {
        throw new InvalidGrantError('Invalid grant: authorization code is invalid');
      }

      if (!code.client) {
        throw new ServerError('Server error: `getAuthorizationCode()` did not return a `client` object');
      }

      if (!code.user) {
        throw new ServerError('Server error: `getAuthorizationCode()` did not return a `user` object');
      }

      if (code.client.id !== client.id) {
        throw new InvalidGrantError('Invalid grant: authorization code is invalid');
      }

      if (!(code.expiresAt instanceof Date)) {
        throw new ServerError('Server error: `expiresAt` must be a Date instance');
      }

      if (code.expiresAt < new Date()) {
        throw new InvalidGrantError('Invalid grant: authorization code has expired');
      }

      if (code.redirectUri && !is.uri(code.redirectUri)) {
        throw new InvalidGrantError('Invalid grant: `redirect_uri` is not a valid URI');
      }

      return code;
    });
};

/**
 * Validate the redirect URI.
 *
 * "The authorization server MUST ensure that the redirect_uri parameter is
 * present if the redirect_uri parameter was included in the initial
 * authorization request as described in Section 4.1.1, and if included
 * ensure that their values are identical."
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
 */

 AuthorizationCodeGrantType.prototype.validateRedirectUri = function(request, code) {
  debug("======AuthorizationCodeGrantType: validateRedirectUri======")
   if (!code.redirectUri) {
     return;
   }

   var redirectUri = request.body.redirect_uri || request.query.redirect_uri;

   if (!is.uri(redirectUri)) {
     throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
   }

   if (redirectUri !== code.redirectUri) {
     throw new InvalidRequestError('Invalid request: `redirect_uri` is invalid');
   }
 };

/**
 * Revoke the authorization code.
 *
 * "The authorization code MUST expire shortly after it is issued to mitigate
 * the risk of leaks. [...] If an authorization code is used more than once,
 * the authorization server MUST deny the request."
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
 */

AuthorizationCodeGrantType.prototype.revokeAuthorizationCode = function(code) {
  debug("======AuthorizationCodeGrantType: revokeAuthorizationCode======")
  return promisify(this.model.revokeAuthorizationCode, 1).call(this.model, code)
    .then(function(code) {

      if (!code) {
        throw new InvalidGrantError('Invalid grant: authorization code is invalid');
      }

      debug(!code.valid ? "==> Authorization Code "+code.code+" Revoked" : "==> Authorization Code "+code.code+" Not Revoked")

      return code;
    });
};

/**
 * Revoke tokens associated with the authorization code.
 *
 */

AuthorizationCodeGrantType.prototype.revokeTokens = function(code) {
  debug("======AuthorizationCodeGrantType: revokeTokens======")
  var revoke_access = promisify(this.model.revokeAccessToken, 4).call(this.model, null, code.code, code.client.id, null);
  var revoke_refresh = promisify(this.model.revokeRefreshToken, 3).call(this.model, null, code.code, code.client.id);

  return Promise.all([revoke_access, revoke_refresh]).then(function(results) {
    debug((results[0] && !results[0].valid) ? "==> Access Token "+results[0].access_token+" Revoked" : "==> Access Token "+results[0].access_token+" Not Revoked")
    debug((results[1] && !results[1].valid) ? "==> Refresh Token "+results[1].refresh_token+" Revoked" : "==> Refresh Token "+results[1].refresh_token+" Not Revoked")

    throw new InvalidGrantError('Invalid grant: authorization code is invalid');
  })
};

/**
 * Save token.
 */

AuthorizationCodeGrantType.prototype.saveToken = function(user, client, authorizationCode, scope, request) {
  debug("======AuthorizationCodeGrantType: saveToken======")
  var fns = [
    this.validateScope(user, client, scope),
    this.generateAccessToken(client, user, scope),
    this.generateRefreshToken(client, user, scope),
    this.getAccessTokenExpiresAt(),
    this.getRefreshTokenExpiresAt(),
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(scope, accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt) {
      var token = {
        accessToken: accessToken,
        authorizationCode: authorizationCode,
        accessTokenExpiresAt: accessTokenExpiresAt,
        refreshToken: refreshToken,
        refreshTokenExpiresAt: refreshTokenExpiresAt,
        userData: user,
        code: authorizationCode,
        scope: scope
      };

      return promisify(this.model.saveToken, 3).call(this.model, token, client, user);
    });
};

/**
 * Generate Id token.
 */

AuthorizationCodeGrantType.prototype.idToken = function(data) {
  debug("======AuthorizationCodeGrantType: idToken======")

  var fns = [
    this.generateIDToken(data.client, data.userData)
  ];

  if (data.scope.includes('openid')) {
    fns.push(this.generateAtHash(data.accessToken))
  }

  return Promise.all(fns)
    .bind(this)
    .spread(function(id_token, at_hash) {
      
      if (at_hash) {
        id_token['at_hash'] = at_hash
      }

      data['id_token'] = id_token
      return data;
    });
  
}

/**
 * Firm Id token.
 */

AuthorizationCodeGrantType.prototype.firmIdToken = function(data) {
  debug("======AuthorizationCodeGrantType: firmIdToken======")
  debug(data.id_token)
  let firmed_id_token = this.generateIDTokenFirmed(data.client.jwt_secret, data.id_token)
  data.id_token = firmed_id_token
  debug(data.id_token)
  return data 
}

/**
 * Export constructor.
 */

module.exports = AuthorizationCodeGrantType;
