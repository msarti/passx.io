  'use strict';
  var _config;
  var keepassio = require('keepass.io');
  var q = require('q');

  var _verifyPassword = function (filename, password) {
    var deferred = q.defer();
    var db = new keepassio.Database();
    try {
      db.addCredential(new keepassio.Credentials.Password(password));
      db.loadFile(filename, function (error) {
        if (error) {
          deferred.reject(error);
        }
        else {
          deferred.resolve();
        }
      });
    }
    catch (e) {
      deferred.reject(e);
    }
    return deferred.promise;
  };

  var convertToDtoGroup = function(group, parent, removeChildren) {

    var obj = JSON.parse(JSON.stringify(group));
    if(removeChildren) {
      delete obj['Group'];
    }
    obj.UUID = new Buffer(group.UUID, 'base64').toString('hex');
    if(group.LastTopVisibleEntry) {
      obj.LastTopVisibleEntry = new Buffer(group.LastTopVisibleEntry, 'base64').toString('hex');
    }
    if(parent) {
      obj.parentUUID = new Buffer(parent.UUID, 'base64').toString('hex');
    }
    if(obj['Entry']) {
      var listEntry = [];
      iterateEntries(obj['Entry'], obj, function(_entry, _group) {
        console.log('Entry '+_entry);
        var copy = JSON.parse(JSON.stringify(_entry));
        copy.UUID = new Buffer(_entry.UUID, 'base64').toString('hex');
        listEntry.push(copy);
      });
      obj['Entry'] = listEntry;
    }

    return obj;
  };

  var walkTree = function(current, type, parent, callback) {
    if(Array.isArray(current)) {
      for(var elem in current) {
        walkTree(current[elem], type, parent, callback);
      }
    } else {
      if(!callback(current, type, parent)) {
        if(current.Entry) {
          walkTree(current.Entry, "Entry", current, callback);
        }
        if(current.Group) {
          walkTree(current.Group, "Group", current, callback);
        }
      }
    }
  };

  var iterateGroups = function(current, parent, callback) {
    if(Array.isArray(current)) {
      for(var elem in current) {

        iterateGroups(current[elem], parent, callback);
      }
    } else {

      if(! callback(current, parent) && current.Group) {
        iterateGroups(current.Group, current, callback);
      }
    }
  };

  var iterateEntries = function(entries, parent, callback) {
    if(Array.isArray(entries)) {
      for(var entry in entries) {
          callback(entries[entry], parent);
      }
    } else if(entries) {
      callback(entries, parent);
    }
  }

  var _findGroups = function(db) {
    var deferred = q.defer();
        _getDbData(db).then(
          function(data) {
            var result = [];
            var root = data.KeePassFile.Root;
            if(root.Group) {
              iterateGroups(root.Group, null, function(current, parent) {
                var obj = convertToDtoGroup(current, parent, true);
                result.push(obj);
                return false;
              });
            }


            deferred.resolve(result);
          }, function(error) {
            deferred.reject(error);
          });
          return deferred.promise;

  };

  var _findGroup = function(db, group_id) {
    var deferred = q.defer();
    _getDbData(db).then(
      function(data) {
        var result = null;
        var root = data.KeePassFile.Root;
        if(root.Group) {
          iterateGroups(root.Group, null, function(current, parent) {

            if(current.UUID === new Buffer(group_id, 'hex').toString('base64')) {
              result = convertToDtoGroup(current, parent, true);
              return true;
            } else {
              return false;
            }
          });
        }
        if(result) {
          deferred.resolve(result);
        } else {
          deferred.reject('Not found');
        }

      }, function(error) {
        deferred.reject(error);
      });
      return deferred.promise;
  };

  var _getDbData = function(db) {
    var deferred = q.defer();
    var rawApi = db.getRawApi();
    try {
      var data = rawApi.get();
      deferred.resolve(data);
    } catch (ex) {
      deferred.reject(ex);
    }
    return deferred.promise;
  };




  module.exports = function(config) {
    _config = config;






    return {
      verifyPassword: _verifyPassword,
      loadKeepass: function () {
        var fun = function (req, res, next) {
          var password = req.credentials.password;
          var filename = req.credentials.filename;
          var db = new keepassio.Database();
          try {
            db.addCredential(new keepassio.Credentials.Password(password));
            db.loadFile(filename, function (error) {
              if (error) {
                res.status(401).send({msg: "unauthorized - invalid password"});
              }
              else {
                req.database = db;
                next();
              }
            });
          }
          catch (e) {
            res.status(401).send({msg: "unauthorized - invalid password"});
          };
        };
        fun.unless = require('express-unless');
        return fun;
      },
      getDbData: _getDbData,
      setDbData: function(db, data) {
        var deferred = q.defer();
        var rawApi = db.getRawApi();
        try {
          rawApi.set(data);
          deferred.resolve(db);
        } catch (ex) {
          deferred.reject(ex);
        }
        return deferred.promise;
      },
      saveFile: function(db, filename) {
        var deferred = q.defer();
        db.saveFile(filename, function(error) {
          if(error) {
            deferred.reject(error);
          } else {
            deferred.resolve(db);
          }
        });
      },
      findGroup: _findGroup,
      findGroups: _findGroups

    };
  }
