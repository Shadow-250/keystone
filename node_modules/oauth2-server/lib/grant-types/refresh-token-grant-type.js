'use strict';

/**
 * Module dependencies.
 */

var AbstractGrantType = require('./abstract-grant-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidGrantError = require('../errors/invalid-grant-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var ServerError = require('../errors/server-error');
var is = require('../validator/is');
var util = require('util');
var debug = require('debug')('oauth2-server: refresh-token-grant-type');

/**
 * Constructor.
 */

function RefreshTokenGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getRefreshToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getRefreshToken()`');
  }

  if (!options.model.revokeRefreshToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `revokeToken()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(RefreshTokenGrantType, AbstractGrantType);

/**
 * Handle refresh token grant.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-6
 */

RefreshTokenGrantType.prototype.handle = function(request, client) {
  debug("======RefreshTokenGrantType: handle======")
  if (!request) {
    throw new InvalidArgumentError('Missing parameter: `request`');
  }

  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  var scope = this.getScope(request);

  return Promise.bind(this)
    .then(function() {
      return this.getRefreshToken(request, client);
    })
    .tap(function(token) {
      return this.revokeToken(token);
    })
    .then(function(token) {
      return this.saveToken(token.user, client, scope);
    });
};

/**
 * Get refresh token.
 */

RefreshTokenGrantType.prototype.getRefreshToken = function(request, client) {
  debug("======RefreshTokenGrantType: getRefreshToken======")
  if (!request.body.refresh_token) {
    throw new InvalidRequestError('Missing parameter: `refresh_token`');
  }

  if (!is.vschar(request.body.refresh_token)) {
    throw new InvalidRequestError('Invalid parameter: `refresh_token`');
  }

  return promisify(this.model.getRefreshToken, 1).call(this.model, request.body.refresh_token)
    .then(function(token) {

      if (!token) {
        throw new InvalidGrantError('Invalid grant: refresh token is invalid');
      }

      if (!token.client) {
        throw new ServerError('Server error: `getRefreshToken()` did not return a `client` object');
      }

      if (token.client.id !== client.id) {
        throw new InvalidGrantError('Invalid grant: refresh token is invalid');
      }

      if (!token.valid) {
        throw new InvalidGrantError('Invalid grant: refresh token is no longer valid');
      }

      if (token.expires && !(token.expires instanceof Date)) {
        throw new ServerError('Server error: `expires` must be a Date instance');
      }

      if (token.expires && token.expires < new Date()) {
        throw new InvalidGrantError('Invalid grant: refresh token has expired');
      }

      return token;
    });
};

/**
 * Revoke the refresh token.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-6
 */

RefreshTokenGrantType.prototype.revokeToken = function(token) {
  debug("======RefreshTokenGrantType: revokeToken======")
  if (this.alwaysIssueNewRefreshToken === false) {
    return Promise.resolve(token);
  }

  return promisify(this.model.revokeRefreshToken, 3).call(this.model, token.token, null, token.client.id)
    .then(function(rT) {
      if (!rT) {
        throw new InvalidGrantError('Invalid grant: refresh token is invalid');
      }
      debug(!rT.valid ? "==> Refresh Token "+rT.refresh_token+" Revoked" : "==> Refresh Token "+rT.refresh_token+" Not Revoked")

      return token;
    });
};

/**
 * Save token.
 */

RefreshTokenGrantType.prototype.saveToken = function(user, client, scope) {
  debug("======RefreshTokenGrantType: saveToken======")
  var fns = [
    this.validateScope(user, client, scope),
    this.generateAccessToken(client, user, scope),
    this.generateRefreshToken(client, user, scope),
    this.getAccessTokenExpiresAt(),
    this.getRefreshTokenExpiresAt()
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(scope, accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt) {
      var token = {
        accessToken: accessToken,
        accessTokenExpiresAt: accessTokenExpiresAt,
        scope: scope
      };

      if (this.alwaysIssueNewRefreshToken !== false) {
        token.refreshToken = refreshToken;
        token.refreshTokenExpiresAt = refreshTokenExpiresAt;
      }

      return token;
    })
    .then(function(token) {
      return promisify(this.model.saveToken, 3).call(this.model, token, client, user)
        .then(function(savedToken) {
          return savedToken;
        });
    });
};

/**
 * Export constructor.
 */

module.exports = RefreshTokenGrantType;
