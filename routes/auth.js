var _ = require('underscore');
var jwt = require('jsonwebtoken');

module.exports = function(app, config) {
    var keepass = require('../lib/keepass')(config);
    var jwtCrypto = require('../lib/jwt-crypto')(config);

    app.post('/auth', function(req, res) {
      var password = req.body.password;
      var filename = config.databasePath;
      if (_.isEmpty(password)) {
          res.status(401).send({msg: "please set a password"});
      } else {
        keepass.verifyPassword(filename, password)
          .then(function () {
              console.log("token");
              var payload = {filename: filename, password: password};
              var encryptedPayload = jwtCrypto.encrypt(payload);
              console.log("token");
              var token = jwt.sign({payload: encryptedPayload}, config.secret, {expiresInMinutes: 100});
              console.log(token);
              res.json({jwt: token});
          }, function (reason) {
              res.status(500).send({msg: "problem occurred reading: " + reason});
          });
      };
    });

    
}
