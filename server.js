 (function () {
  "use strict";

	var optional = require('require-optional');
    var express  = require('express');
    var app      = express();                               // create our app w/ express
    var morgan = require('morgan');             // log requests to the console (express4)
    var bodyParser = require('body-parser');    // pull information from HTML POST (express4)
    var methodOverride = require('method-override'); // simulate DELETE and PUT (express4)
    var expressJwt = require('express-jwt');

    var port = 8080;
	  var config = optional('./passx', {"port": port, databasePath: './test/example.kdbx', secret: 'changeme!!', jwtUserProperty: 'jwt'});



    app.use(express.static(__dirname + '/public'));                 // set the static files location /public/img will be /img for users
    app.use(morgan('dev'));                                         // log every request to the console
    app.use(bodyParser.urlencoded({'extended':'true'}));            // parse application/x-www-form-urlencoded
    app.use(bodyParser.json());                                     // parse application/json
    app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
    app.use(methodOverride());

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


    app.use(expressJwt(jwtConfig).unless({path: anonymousAuthorizedPaths}));
    var jwtCrypto = require('./lib/jwt-crypto')(config);
    app.use(jwtCrypto.decryptJwt().unless({path: anonymousAuthorizedPaths}));
    var keepass = require('./lib/keepass')(config);
    app.use(keepass.loadKeepass().unless({path: anonymousAuthorizedPaths}));


    var auth = require('./routes/auth')(app, config);
    require('./routes/api')(app, config);



    //app.use(applib.Backend(config));

    // listen (start app with node server.js) ======================================
    app.listen(config.port);
    console.log("App listening on port " + config.port);
})();
