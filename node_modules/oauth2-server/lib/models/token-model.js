'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');

/**
 * Constructor.
 */

var modelAttributes = ['accessToken', 'accessTokenExpiresAt', 'refreshToken', 'refreshTokenExpiresAt', 'scope', 'id_token', 'client', 'user'];

function TokenModel(data, options) {
  data = data || {};

  if (data.scope == 'openid' && !data.id_token && data.client.grant_type =='authorization_code') {
    throw new InvalidArgumentError('Missing parameter: `idToken`');
  }

  if (!data.accessToken) {
    throw new InvalidArgumentError('Missing parameter: `accessToken`');
  }

  if (!data.client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  if (!Object.keys(data).some(elem => (['user', 'iot'].includes(elem) && data.elem !== null)) && (data.client.grants.indexOf('client_credentials') == -1) ) {
    throw new InvalidArgumentError('Missing parameter: `user`');
  }

  if (data.accessTokenExpiresAt && !(data.accessTokenExpiresAt instanceof Date)) {
    throw new InvalidArgumentError('Invalid parameter: `accessTokenExpiresAt`');
  }

  if (data.refreshTokenExpiresAt && !(data.refreshTokenExpiresAt instanceof Date)) {
    throw new InvalidArgumentError('Invalid parameter: `refreshTokenExpiresAt`');
  }

  this.accessToken = data.accessToken;
  this.idToken = data.id_token;
  this.accessTokenExpiresAt = data.accessTokenExpiresAt;
  this.client = data.client;
  this.refreshToken = data.refreshToken;
  this.refreshTokenExpiresAt = data.refreshTokenExpiresAt;
  this.scope = data.scope;
  this.user = (data.user) ? data.user : null;
  this.iot = (data.iot) ? data.iot : null;

  if (options && options.allowExtendedTokenAttributes) {
    this.customAttributes = {};

    for (var key in data) {
      if (data.hasOwnProperty(key) && (modelAttributes.indexOf(key) < 0)) {
        this.customAttributes[key] = data[key];
      }
    }
  }

  if(this.accessTokenExpiresAt) {
    this.accessTokenLifetime = Math.floor((this.accessTokenExpiresAt - new Date()) / 1000);
  }
}

/**
 * Export constructor.
 */

module.exports = TokenModel;
