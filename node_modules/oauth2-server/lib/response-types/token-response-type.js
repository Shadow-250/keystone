'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: token-response-type');

/**
 * Constructor.
 */

function TokenResponseType(token) {
	if (!token) {
    throw new InvalidArgumentError('Missing parameter: `token`');
  }
  
  this.token = token;
}

/**
 * Build redirect uri.
 */

TokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======TokenResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);
  uri.query.token_type = "Bearer";
  if (this.token.accessTokenExpiresAt) {
    uri.query.expires_at = this.token.accessTokenExpiresAt.toString();
  }
  uri.query.token = this.token.accessToken;

  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = TokenResponseType;
