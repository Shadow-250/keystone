'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: code-id-token-response-type');
/**
 * Constructor.
 */

function CodeIDTokenResponseType(authCode, code_id_token) {
  if (!authCode) {
    throw new InvalidArgumentError('Missing parameter: `code`');
  }
  if (!code_id_token.id_token) {
    throw new InvalidArgumentError('Missing parameter: `id_token`');
  }

  this.code = authCode;
  this.id_token = code_id_token.id_token;
}

/**
 * Build redirect uri.
 */

CodeIDTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======CodeIDTokenResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);

  uri.query.code = this.code;
  uri.query.id_token = this.id_token;
  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = CodeIDTokenResponseType;
