

module.exports = function(app, config) {
  var keepass = require('../lib/keepass')(config);
  var q = require('q');

  app.post('/db', function(req, res) {

    var data = req.body;

    keepass.setDbData(req.database, data).then(
      function() {
        res.json({message: "OK"});
      }, function(error) {
        res.status(500).send({message: error});
      }
    );
  });

  app.get('/db', function(req, res) {
    keepass.getDbData(req.database).then(
      function(data) {
        res.json(data);
      }, function(error) {
        res.status(500).send({message: error});
      }
    );
  });

  app.get('/groups', function(req, res) {
    keepass.findGroups(req.database).then(
      function(grp) {
        res.json(grp);
      }, function(error) {
        res.status(500).send({message: error});
      });
    });



  app.get('/groups/:group_id', function(req, res) {
    keepass.findGroup(req.database, req.params.group_id).then(
      function(grp) {
        res.json(grp);
      }, function(error) {
        res.status(500).send({message: error});
      }
    );

  });

  app.get('/groups/:group_id/entries', function(req, res) {
    var basicApi = req.database.getBasicApi();
    res.json(basicApi.getEntries(req.params.group_id));
  });

  app.post('/groups/:group_id/entries', function(req, res) {
    var basicApi = req.database.getBasicApi();
    var data = req.body;
    basicApi.setEntries(req.params.group_id, data);
    res.json({ message: 'Ok' });
  });

};
