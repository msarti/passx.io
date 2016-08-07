var keepassio = require('../lib/keepassio');


this.suite1 = {
    'test one': function (test) {
      try {
      keepassio.loadDatabase('./test/example.kdbx', '', function(err, headers)  {
          console.log("prova");
          if(err) {
            test.ok(false);
          } else {
            test.ok(true);
          }

      });
      test.done();
    } catch (ex) {
      console.log(ex, ex.stack.split("\n"));
    }

    }
};
