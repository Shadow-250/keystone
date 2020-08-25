'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: code-id-token-token-response-type');
/**
 * Constructor.
 */

function CodeIDTokenTokenResponseType(authCode, code_id_token_token) {
  debug("LLEGA AQUI"+code_id_token_token)
  if (!authCode) {
    throw new InvalidArgumentError('Missing parameter: `code`');
  }
  if (!code_id_token_token.id_token) {
    throw new InvalidArgumentError('Missing parameter: `id_token`');
  }
  if (!code_id_token_token.accessToken) {
    throw new InvalidArgumentError('Missing parameter: `token`');
  }

  this.code = authCode;
  this.token = code_id_token_token;
}

/**
 * Build redirect uri.
 */

CodeIDTokenTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======CodeIDTokenTokenResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);
  uri.query.token_type = "bearer";
  if (this.token.accessTokenExpiresAt) {
    uri.query.expires_in = this.token.client.accessTokenLifetime;
    //uri.query.expires_in = this.token.accessTokenExpiresAt.toString();
  }
  uri.query.id_token = this.token.id_token;
  uri.query.token = this.token.accessToken;
  uri.query.code = this.code;

  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = CodeIDTokenTokenResponseType;
