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


function KeepassDb(path, passphrase) {
  this.path = path;
  this.passphrase = passphrase;

};

KeepassDb.prototype.loadDatabase = function() {
  loadDatabase(this.path, this.passphrase, (err, db) => {
    if(err) {
      throw err;
    } else {
      this.fileContent = db.fileContent;
      this.headers = db.headers;
      this.rawData = db.rawData;
      this.dirty = false;
    }

  });
}




var loadDatabase = function(path, passphrase, callback) {
  loadFile(path, (err, fileContent) => {
    if(err) {
      callback(err);
    } else {
      var hmap = {}
      var headers = {};
      var encryptedPayload;
      headers.primaryIdentifier = fileContent.slice(0, 4);
      headers.secondaryIdentifier = fileContent.slice(4, 8);
      headers.fileVersionMinor = fileContent.readUInt8(8);
      headers.fileVersionMajor = fileContent.readUInt8(10);
      var pos = 12;
      while(true){
        var type = fileContent.readUInt8(pos);

        pos += 1;
        var len = fileContent.readUInt16LE(pos);
        pos += 2;
        var val = fileContent.slice(pos, pos+len);
        pos += len;
        hmap[type] = val;
        if(type === 0) {
          encryptedPayload = fileContent.slice(pos);
          headers.rawBuffer = fileContent.slice(0, pos);
          break;
        }
      }
      headers.cipherID = hmap[2];
      headers.compression = hmap[3].readUInt32LE();
      headers.masterSeed = hmap[4];
      headers.transformSeed = hmap[5];
      headers.transformRounds = hmap[6].readUInt32LE();
      headers.encryptionIV = hmap[7];
      headers.protectedStreamKey = hmap[8];
      headers.streamStartBytes = hmap[9];
      headers.innerRandomStreamID = hmap[10].readUInt32LE();



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

      var plainPayload = decrypt(encryptedPayload);

      if(! plainPayload.slice(0,headers.streamStartBytes.length).
      equals(headers.streamStartBytes) ){
        callback('Error in decoded payload verification');
        return;
      };
      var ppos = headers.streamStartBytes.length;

      var payload = [];

      while(ppos < plainPayload.length) {
        var payloadBlock = {};

        payloadBlock.blockID = plainPayload.slice(ppos, ppos+4).readUInt32LE();
        ppos += 4;
        payloadBlock.hash = plainPayload.slice(ppos, ppos+32);
        ppos += 32;
        payloadBlock.length = plainPayload.slice(ppos, ppos+4).readUInt32LE();
        ppos += 4;
        payloadBlock.data = plainPayload.slice(ppos, ppos+payloadBlock.length);
        ppos += payloadBlock.length;

        if(payloadBlock.length > 0) {
          payload.push(payloadBlock.data);
        }
      };
      var data = Buffer.concat(payload);

      if(headers.compression) {
        console.log('DECOMPRESS');
        data = zlib.gunzipSync(data);
      }
      var processValues = function(str) {
        if(! isNaN(str)) {
          str = str % 1 === 0 ? parseInt(str, 10) : parseFloat(str);
        } else if (/^(?:true|false)$/i.test(str)) {
          str = str.toLowerCase() === 'true';
        }
        return str;
      }



      var parseString = require('xml2js').parseString;
      parseString(data.toString('utf8'), {explicitArray: false, valueProcessors: [processValues]}, (err, result) => {
        var db = {
          fileContent : fileContent,
          headers : headers,
          rawData : result,
          dirty: false
        };
        callback(null, db);
      });




    };

  });



}; //loadDatabase



module.exports = {
  loadFile : loadFile,
  loadDatabase: loadDatabase,
  KeepassDb: KeepassDb
}
