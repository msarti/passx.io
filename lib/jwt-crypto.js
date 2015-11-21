
  'use strict';

  var AES = require('crypto-js/aes');
  var UTF8 = require('crypto-js/enc-utf8');

  module.exports = function (config) {
  	return {
	    decryptJwt: function () {
	      return function (req, res, next) {
	        if (req.user) {
	          var decrypted = AES.decrypt(req.user.payload, config.secret);
	          req.credentials = JSON.parse(decrypted.toString(UTF8));
	        }
	        next();
	      };
	    },
  	  	encrypt: function (payload) {
  	  		return AES.encrypt(JSON.stringify(payload), config.secret).toString();
    	}
  	};
  };
