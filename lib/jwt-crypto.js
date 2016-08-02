
  'use strict';

  var AES = require('crypto-js/aes');
  var UTF8 = require('crypto-js/enc-utf8');

  module.exports = function (config) {
  	return {
	    decryptJwt: function () {

	      var fun = function (req, res, next) {
	        if (req.user) {
            console.log(req.user.payload);
            try {
	             var decrypted = AES.decrypt(req.user.payload, config.secret);
	             req.credentials = JSON.parse(decrypted.toString(UTF8));
            } catch (error) {
              res.status(401).send({msg: "unauthorized"});
            }
	        }
	        next();
	      };
        fun.unless = require('express-unless');
        return fun;
	    },
  	  	encrypt: function (payload) {
  	  		var encryptedPayload  = AES.encrypt(JSON.stringify(payload), config.secret).toString();
          console.log(encryptedPayload);
          return encryptedPayload;
    	}
  	};
  };
