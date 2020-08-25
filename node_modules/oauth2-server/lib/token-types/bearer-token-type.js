'use strict';

var debug = require('debug')('oauth2-server: bearer-token-type');

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');

/**
 * Constructor.
 */

function BearerTokenType(accessToken, idToken, accessTokenLifetime, refreshToken, scope, customAttributes) {
  if (!accessToken) {
    throw new InvalidArgumentError('Missing parameter: `accessToken`');
  }

  this.accessToken = accessToken;
  this.accessTokenLifetime = accessTokenLifetime;
  this.refreshToken = refreshToken;
  this.idToken = idToken;
  this.scope = scope;

  if (customAttributes) {
    this.customAttributes = customAttributes;
  }
}

/**
 * Retrieve the value representation.
 */

BearerTokenType.prototype.valueOf = function() {
  debug("======BearerTokenType: valueOf======")
  var object = {
    access_token: this.accessToken,
    token_type: 'bearer'
  };

  if(this.scope == 'openid'){
    object.id_token = this.idToken;
  }

  if (this.accessTokenLifetime) {
    object.expires_in = this.accessTokenLifetime;
  }

  if (this.refreshToken) {
    object.refresh_token = this.refreshToken;
  }

  if (this.scope) {
    object.scope = this.scope;
  }

  for (var key in this.customAttributes) {
    if (this.customAttributes.hasOwnProperty(key)) {
      object[key] = this.customAttributes[key];
    }
  }
  return object;
};

/**
 * Export constructor.
 */

module.exports = BearerTokenType;
