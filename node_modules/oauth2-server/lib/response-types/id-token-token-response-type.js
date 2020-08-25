'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: id-token-token-response-type');

/**
 * Constructor.
 */

function IDTokenTokenResponseType(id_token_token) {
	/*debug("*******ID_TOKEN_TOKEN*****")
	debug(Object.values(id_token_token))*/
	if (!(id_token_token.id_token)) {
    throw new InvalidArgumentError('Missing parameter: `id_token`');
  }
  if (!(id_token_token.accessToken)) {
    throw new InvalidArgumentError('Missing parameter: `access_token`');
  }

  //this.id_token = id_token;
  this.token = id_token_token;
}

/**
 * Build redirect uri.
 */

IDTokenTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======IDTokenTokenResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);
  uri.query.token_type = "bearer";
  if (this.token.accessTokenExpiresAt) {
		//debug(this.token.accessTokenExpiresAt)
    //uri.query.expires_in = this.token.accessTokenExpiresAt.toString();
		uri.query.expires_in = this.token.client.accessTokenLifetime;
  }
  uri.query.id_token = this.token.id_token;
  uri.query.token = this.token.accessToken;

  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = IDTokenTokenResponseType;
