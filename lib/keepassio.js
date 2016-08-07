'use strict';

var fs = require('fs');

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

      console.log(headers);


      callback(null, headers);
    };

  });



}; //loadDatabase



module.exports = {
  loadFile : loadFile,
  loadDatabase: loadDatabase
}
