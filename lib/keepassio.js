'use strict';

var fs = require('fs');
var crypto = require('crypto');
var zlib = require('zlib');
var q = require('q');

var loadFile = function(path, callback) {
    fs.readFile(path, function(err, data) {
        if(err) {
          callback(err);
        } else {
          if(Buffer.compare(data.slice(0,4), new Buffer([0x03,0xD9,0xA2,0x9A])) !== 0) {
            callback("Invalid file header");
          } else {
            callback(null, data);
          }
        };
      });
};

var hash = function (input) {
  return crypto.createHash('sha256').update(input).digest();
};




var loadDatabase = function(path, passphrase, callback) {
  loadFile(path, (err, data) => {
    if(err) {
      callback(err);
    } else {
      var headers = {};
      headers.primaryIdentifier = data.slice(0, 4);
      headers.secondaryIdentifier = data.slice(4, 8);
      headers.fileVersionMinor = data.readUInt8(8);
      headers.fileVersionMajor = data.readUInt8(10);
      var pos = 12;
      while(true){
        var type = data.readUInt8(pos);

        pos += 1;
        var len = data.readUInt16LE(pos);
        pos += 2;
        var val = data.slice(pos, pos+len);
        pos += len;
        headers[type] = val;
        if(type === 0) {
          headers.payload = data.slice(pos);
          break;
        }
      }
      headers.cipherID = headers[2];
      headers.compression = headers[3].readUInt32LE();
      headers.masterSeed = headers[4];
      headers.transformSeed = headers[5];
      headers.transformRounds = headers[6].readUInt32LE();
      headers.encryptionIV = headers[7];
      headers.protectedStreamKey = headers[8];
      headers.streamStartBytes = headers[9];
      headers.innerRandomStreamID = headers[10].readUInt32LE();

      //console.log(headers);

      var createCipher = function () {
        var c = crypto.createCipheriv('aes-256-ecb', headers.transformSeed, new Buffer(0));
        var cipher = function (input) {
          return c.update(input);
        };
        return cipher;
      };
      var cipher = createCipher();

      var pw_hash = hash(passphrase);
      var composite_key = hash(pw_hash); // other keys would be added here
      var transformed_key = composite_key;

      for(var i=0; i<headers.transformRounds; i++) {
        transformed_key = cipher(transformed_key);
      }

      transformed_key=hash(transformed_key);
      var master_key = hash(Buffer.concat([headers.masterSeed, transformed_key]));
      //console.log('MASTER KEY: ' + master_key.toString('hex')); // you really should not log that in production

      var decrypt = function (input) {
        var c = crypto.createDecipheriv('aes-256-cbc', master_key, headers.encryptionIV);
        return Buffer.concat([c.update(input), c.final()]);
      };

      var plainPayload = decrypt(headers.payload);


      callback(null, headers);
    };

  });



}; //loadDatabase



module.exports = {
  loadFile : loadFile,
  loadDatabase: loadDatabase
}
