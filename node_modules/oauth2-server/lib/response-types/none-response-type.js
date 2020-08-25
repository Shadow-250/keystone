'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: none-response-type');
/**
 * Constructor.
 */

function NoneResponseType(none) {
  if (!none) {
    throw new InvalidArgumentError('Missing parameter: `none`');
  }

  this.none = none;
}

/**
 * Build redirect uri.
 */

NoneResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======NoneResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);
  ////  QUEDA POR HACER!!!!!***********

  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = NoneResponseType;
