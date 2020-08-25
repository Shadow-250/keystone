'use strict';

/**
 * Module dependencies.
 */

var _ = require('lodash');
var OAuthError = require('./oauth-error');
var util = require('util');

/**
 * Constructor.
 *
 * "The authorization server does not supported obtaining an
 * authorization code using this method."
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
 */

function UnsupportedTokenTypeError(message, properties) {
  properties = _.assign({
    code: 400,
    name: 'unsupported_token_type'
  }, properties);

  OAuthError.call(this, message, properties);
}

/**
 * Inherit prototype.
 */

util.inherits(UnsupportedTokenTypeError, OAuthError);

/**
 * Export constructor.
 */

module.exports = UnsupportedTokenTypeError;
