'use strict';

/**
 * Module dependencies.
 */

var crypto = require('crypto');
var randomBytes = require('bluebird').promisify(require('crypto').randomBytes);

/**
 * Export `TokenUtil`.
 */

module.exports = {

  /**
   * Generate random token.
   */

  generateRandomToken: function() {
    return randomBytes(256).then(function(buffer) {
      return crypto
        .createHash('sha1')
        .update(buffer)
        .digest('hex');
    });
  },

  /**
   * Generate Access Token Hash.
   */

  generateAtHash: function(accessToken) {
    let buffer = crypto
        .createHash('sha256')
        .update(accessToken.toString())
        .digest();

    buffer = buffer.slice(0, buffer.length/2).toString('base64');

    return buffer;
  },

  /**
   * Generate Authorization Code Hash.
   */

  generateCHash: function(authorizationCode) {
    let buffer = crypto
        .createHash('sha256')
        .update(authorizationCode.toString())
        .digest();

    buffer = buffer.slice(0, buffer.length/2).toString('base64');

    return buffer;
  }

};
