'use strict';

/**
 * Module dependencies.
 */
const jsonwebtoken = require('jsonwebtoken');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidScopeError = require('../errors/invalid-scope-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var is = require('../validator/is');
var tokenUtil = require('../utils/token-util');
var debug = require('debug')('oauth2-server: abstract-grant-type');
const crypto = require('crypto');


/**
 * Constructor.
 */

function AbstractGrantType(options) {
  options = options || {};

  if (!options.accessTokenLifetime) {
    throw new InvalidArgumentError('Missing parameter: `accessTokenLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  this.accessTokenLifetime = options.accessTokenLifetime;
  this.model = options.model;
  this.refreshTokenLifetime = options.refreshTokenLifetime;
  this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken;
}

/**
 * Generate access token.
 */

AbstractGrantType.prototype.generateAccessToken = function(client, user, scope) {
  debug("======AbstractGrantType: generateAccessToken======")
  if (this.model.generateAccessToken) {
    return promisify(this.model.generateAccessToken, 3).call(this.model, client, user, scope)
      .then(function(accessToken) {
        return accessToken || tokenUtil.generateRandomToken();
      });
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Generate ID Token
 */

AbstractGrantType.prototype.generateIDToken = function(client, user) {
  debug("======AbstractGrantType: generateIDToken======")
  return promisify(this.model.generateIdToken, 2).call(this.model, client, user)
    .then(function(idToken) {
      return idToken;
    });
}

/**
 * Firm ID Token
 */

AbstractGrantType.prototype.generateIDTokenFirmed = function(secret, jwt) {
  debug("======AbstractGrantType: generateIDTokenFirmed======")

  const options = {};

  var idToken = jsonwebtoken.sign(
    jwt,
    secret,
    options
  );

  return idToken
}


/**
 * Generate Access Token Hash
 */

AbstractGrantType.prototype.generateAtHash = function(token) {
  debug("======AbstractGrantType: generateAtHash======")
  return tokenUtil.generateAtHash(token) 
}

/**
 * Generate Code Hash
 */

AbstractGrantType.prototype.generateCHash = function(code) {
  debug("======AbstractGrantType: generateCHash======")
  return tokenUtil.generateCHash(code) 
}


/**
 * Generate refresh token.
 */

AbstractGrantType.prototype.generateRefreshToken = function(client, user, scope) {
  debug("======AbstractGrantType: generateRefreshToken======")
  if (this.model.generateRefreshToken) {
    return promisify(this.model.generateRefreshToken, 3).call(this.model, client, user, scope)
      .then(function(refreshToken) {
        return refreshToken || tokenUtil.generateRandomToken();
      });
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Get access token expiration date.
 */

AbstractGrantType.prototype.getAccessTokenExpiresAt = function() {
  debug("======AbstractGrantType: getAccessTokenExpiresAt======")
  var expires = new Date();

  expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime);

  return expires;
};

/**
 * Get refresh token expiration date.
 */

AbstractGrantType.prototype.getRefreshTokenExpiresAt = function() {
  debug("======AbstractGrantType: getRefreshTokenExpiresAt======")
  var expires = new Date();

  expires.setSeconds(expires.getSeconds() + this.refreshTokenLifetime);

  return expires;
};

/**
 * Get scope from the request body.
 */

AbstractGrantType.prototype.getScope = function(request) {
  debug("======AbstractGrantType: getScope======")
  if (!is.nqschar(request.body.scope)) {
    throw new InvalidArgumentError('Invalid parameter: `scope`');
  }

  return request.body.scope;
};

/**
 * Validate requested scope.
 */
AbstractGrantType.prototype.validateScope = function(user, client, scope) {
  debug("======AbstractGrantType: validateScope======")
  //Creo que esto con openidconnect no seria necesario porque la request al token endpoint no necesita scope???
  if (this.model.validateScope) {
    return promisify(this.model.validateScope, 3).call(this.model, user, client, scope)
      .then(function (scope) {
        if (!scope) {
          throw new InvalidScopeError('Invalid scope: Requested scope is invalid');
        }
        return scope;
      });
  } else {
    return scope;
  }
};

/**
 * Export constructor.
 */

module.exports = AbstractGrantType;
