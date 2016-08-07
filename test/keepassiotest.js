var keepassio = require('../lib/keepassio');


this.suite1 = {
    'test one': function (test) {
      try {
      keepassio.loadDatabase('./test/example.kdbx', 'password', function(err, db)  {
          console.log("prova");
          if(err) {
            test.ok(false);
          } else {
            console.log(JSON.stringify(db.rawData));
            test.ok(true);
          }

      });
      test.done();
    } catch (ex) {
      console.log(ex, ex.stack.split("\n"));
    }

  },
  'test load database' : function(test) {
    try {
      var db = new keepassio.KeepassDb('./test/example.kdbx', 'password');
      db.loadDatabase();
      test.ok(true);
    } catch (ex) {
      test.ok(false);
    }
    test.done();
  }
};
