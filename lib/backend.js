(function () {
  "use strict";

  var express = require('express');
  var expressJwt = require('express-jwt');
  var app = express();
  var _ = require('underscore');
  var jwt = require('jsonwebtoken');


  var createBackend = function (config) {
  	  var keepass = require('./keepass')(config);
      var jwtCrypto = require('./jwt-crypto')(config);
      var anonymousAuthorizedPaths = [
        '/',
        '/favicon.ico',
        /index.html?/,
        /(css|js|templates)\/(.+)/,
        '/auth'
      ];

      var jwtConfig = {secret: config.secret, 
                        getToken: function fromHeaderOrQuerystring (req) {
                          if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
                              return req.headers.authorization.split(' ')[1];
                          } else if (req.query && req.query.token) {
                            return req.query.token;
                          }
                          return null;
                        }
                      };
    

	  var app = express();
    app.use(expressJwt(jwtConfig).unless({path: anonymousAuthorizedPaths}));
    app.use(jwtCrypto.decryptJwt());

    app.post('/auth', function(req, res) {
      var password = req.body.password;
      if (_.isEmpty(password)) {
          res.status(401).send({msg: "please set a password"});
      } else {
        keepass.getDatabaseRaw(password)
          .then(function () {
              var payload = {filename: config.databasePath, password: password};
              var encryptedPayload = jwtCrypto.encrypt(payload);
              var token = jwt.sign({payload: encryptedPayload}, config.secret, {expiresInMinutes: 100});
              res.json({jwt: token});
          }, function (reason) {
              res.status(500).send({msg: "problem occurred reading: " + reason});
          });
      };

    });

    app.get('/groups',
            function (req, res) {
            var password = req.credentials.password;

            keepass.getGroups(password)
                        .then(function (result) {
                            res.json(result);
                        }, function (reason) {
                            res.status(500).send({msg: "problem occurred reading '" + config.databasePath + "': " + reason});
                        });
    });

	  return app;
  };


  module.exports = function (config) {
     return createBackend(config);
  };

})();