(function () {
  'use strict';

  var _config;
  var keepassio = require('keepass.io');
  var q = require('q');


  var loadFile = function (filename, password) {
    var deferred = q.defer();
    var db = new keepassio.Database();
    try {
      db.addCredential(new keepassio.Credentials.Password(password));
      db.loadFile(filename, function (error) {
        if (error) {
          deferred.reject(error);
        }
        else {
          deferred.resolve(db);
        }
      });
    }
    catch (e) {
      deferred.reject(e);
    }
    return deferred.promise;
  };

  var getDatabase = function (password) {
    var deferred = q.defer();

    var filename = _config.databasePath;
    q.when(loadFile(filename, password)).then(function (result) {
      deferred.resolve(result);
    }, function (reason) {
      deferred.reject(reason);
    });
    return deferred.promise;
  };

  var getGroupEntries = function (password, groupId) {
    var deferred = q.defer();

    q.when(getDatabase(password)).then(function (result) {
      var basicApi = result.getBasicApi();
      try {
        var entries = basicApi.getEntries(groupId);
        deferred.resolve(entries);
      }
      catch (e) {
        deferred.reject(e);
      }
    }, function (reason) {
      deferred.reject(reason);
    });
    return deferred.promise;
  };

  var getGroups = function (password) {
    var deferred = q.defer();

    q.when(getDatabase(password)).then(function (result) {
      var basicApi = result.getBasicApi();
      var groups = basicApi.getGroupTree();
      deferred.resolve(groups);
    }, function (reason) {
      deferred.reject(reason);
    });
    return deferred.promise;
  };

   var getDatabaseRaw = function (password) {
    var deferred = q.defer();

    q.when(getDatabase(password)).then(function (result) {
      deferred.resolve(result.getRawApi().get().KeePassFile);
    }, function (reason) {
      deferred.reject(reason);
    });
    return deferred.promise;
  };

   module.exports = function (config) {
   	_config = config;

   	return {
   		getGroupEntries: getGroupEntries,
   		getGroups: getGroups,
   		getDatabaseRaw: getDatabaseRaw
   	};

   };


})();
