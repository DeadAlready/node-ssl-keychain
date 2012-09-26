'use strict';

var fs = require('fs');
var mkdirp = require('mkdirp');
var path = require('path');
var utils = require('./utils');
var crypto = require('crypto');
var exec = require('child_process').exec;

var serial = ~~(Math.random()*10000)%100;

function KeyGen(options){
  if(this instanceof KeyGen === false){
    return new KeyGen(options);
  }
  
  if(!options)
    options = {};
  
  // Give possibility to include bunyan logger
  if(!options.log){
    this.log = function(type, log){
      console.log(log);
    }
  } else {
    this.log = function(type, log){
      options.log[type](log);
    }
  }
  
  this.subj = {
    C:'EE',
    ST:'Harjumaa',
    L:'Tallinn',
    O:'Guardtime',
    OU:'Backup-restore',
    emailAddress:'admin@email.address'
  };
  
  if(options.subj){
    utils.extend(this.subj, options.subj);
  }
  
  this.size = options.size || 4096;
  
  this.root = options.root || process.cwd() + path.sep;
  this.folder = this.root + utils.fixPath(options.folder || 'certs');
  
}

module.exports = KeyGen;

/**
 * Function returning an object containing absolute paths to keys
 * 
 * @param name {String}  name of key
 * @param csr  {Boolean}  wheter to return csr path
 */
KeyGen.prototype._keyPair = function _keyPair(name, csr){
  if(name.indexOf(path.sep) === -1){
    name = name + path.sep + name;
  }
  
  var pair = {
    key: this.folder + name + '.key',
    crt: this.folder + name + '.crt'
  };
  if(csr){
    pair.csr = this.folder + name + '.csr';
  }
  return pair;
}

/**
 * Function returning the -subj part of openssl commands
 * 
 * @param name {String}  name of the certificate
 */
KeyGen.prototype._subject = function _subject(name){
  var subject = '';
  for(var i in this.subj){
    subject += '/' + i + '=' + this.subj[i];
  }
  
  subject += '/CN='+ _subjectName(name);
  return subject;
}

/**
 * Function for creating a RSA key
 * 
 * @param name {String}  certificate name
 * @param callback {Function}
 */
KeyGen.prototype.createKey = function createKey(name, callback){
  var pair = this._keyPair(name);
  var self = this;
  _createPath(pair.key,utils.cC(callback, function(){
    exec(utils.str('openssl genrsa -out :name: :size:', {name:pair.key, size:self.size}), utils.cC(callback));
  }));
}

/**
 * Function for checking and upon necessity creating a RSA key
 * 
 * @param name {String}  certificate name
 * @param callback {Function}
 */
KeyGen.prototype.checkCreateKey = function checkCreateKey(name, callback){
  var pair = this._keyPair(name);
  var self = this;
  fs.stat(pair.key,function(err,stat){
    if(err){
      self.createKey(name, callback);
    } else {
      callback(null, true);
    }
  });
}

/**
 * Function for checking and upon necessity creating a cert
 * 
 * @param name {String}  certificate name
 * @param callback {Function}
 */
KeyGen.prototype.checkCreateCert = function checkCreateCert(name, ca, force, callback){
  var pair = this._keyPair(name);
  var self = this;
  if(force){
    self.createCert(name, ca, callback);
  } else {
    fs.stat(pair.crt,function(err,stat){
      if(err){
        self.createCert(name, ca, callback);
      } else {
        callback();
      }
    });
  }
}

/**
 * Function for creating a cert
 * 
 * @param name {String}  certificate name
 * @param callback {Function}
 */
KeyGen.prototype.createCert = function createCert(name, ca, callback){
  var pair = this._keyPair(name);
  var self = this;
  self.createSignRequest(name, utils.cC(callback, function(){
    self.sign(name, ca, utils.cC(callback,function(){
      callback(null, pair);
    }));
  }));
}

/**
 * Function for creating a certificate signing request
 * 
 * @param name {String}  name of key
 * @param callback {Function}
 */
KeyGen.prototype.createSignRequest = function createSignRequest(name, callback){
  var pair = this._keyPair(name, true);
  pair.subj = this._subject(name);
  this.checkCreateKey(name, utils.cC(callback, function(){
    exec(utils.str('openssl req -new -subj :subj: -key :key: -out :csr:', pair), utils.cC(callback));
  }));
}

/**
 * Function for creating a CA cert from key
 * 
 * @param name {String}  name of file to sign
 * @param callback {Function}
 */
KeyGen.prototype.sign = function sign(name, ca, callback){
  if(ca instanceof Function){
    callback = ca;
    this.signCA(name, callback);
  } else if(ca === false) { 
    this.signCA(name, callback);
  } else {
    this.signRequest(name, ca, callback);
  }
}

/**
 * Function for creating a CA cert from key if it doesn't exist
 * 
 * @param name {String}  name of file to sign
 * @param callback {Function}
 */
KeyGen.prototype.checkSign = function checkSign(name, ca, force, callback){
  var self = this;
  if(force){
    return self.sign(name, ca, callback);
  } 
  
  var pair = self._keyPair(name);
  fs.stat(pair.crt, function(err,stats){
    if(err){
      self.sign(name, ca, callback);
    } else {
      callback(null, true);
    }
  });
}

/**
 * Function for creating a CA cert from key
 * 
 * @param name {String}  name of key
 * @param callback {Function}
 */
KeyGen.prototype.signCA = function signCA(name, callback){
  var pair = this._keyPair(name);
  pair.subj = this._subject(name);
  
  exec(utils.str('openssl req -new -subj :subj: -x509 -days 365 -key :key: -out :crt:', pair), utils.cC(callback));
}

/**
 * Function for signing a certificate signing request
 * 
 * @param name {String}  name of key
 * @param keyName {String}  name of CA to use
 * @param callback {Function}
 */
KeyGen.prototype.signRequest = function signRequest(name, ca, callback){
  var pair = this._keyPair(name, true);
  
  var opts = {
    csr: pair.csr,
    crt: pair.crt,
    caCert: ca.crt,
    caKey: ca.key,
    serial: '0' + (serial++)
  }
  exec(utils.str('openssl x509 -req -days 365 -in :csr: -CA :caCert: -CAkey :caKey: -set_serial :serial: -out :crt:', opts), utils.cC(callback));
}

/**
 * Function for creating a self signed CA
 * 
 * @param name {String}  certificate name
 * @param callback {Function}
 */
KeyGen.prototype.createCA = function createCA(name, callback){
  var self = this;
  self.createKey(name, utils.cC(callback,function(){
    self.sign(name, utils.cC(callback,function(){
      var pair = self._keyPair(name);
      pair.created = true;
      callback(null, pair);
    }));
  }));
}

/**
 * Function for checking and if necessary creating a self signed CA
 * 
 * @param name {String}  certificate name
 * @param callback {Function}
 */
KeyGen.prototype.checkCreateCA = function checkCreateCA(name, callback){
  var self = this;
  self.checkCreateKey(name, utils.cC(callback,function(existed){
    self.checkSign(name, false, !existed, utils.cC(callback,function(certExisted){
      var pair = self._keyPair(name);
      pair.created = !(existed && certExisted);
      callback(null, pair);
    }));
  }));
}

/**
 * Function for creating a self signed keypair
 * 
 * @param name {String}  certificate name
 * @param callback {Function}
 */
KeyGen.prototype.createSelfSigned = function createSelfSigned(name, ca, callback){
  var self = this;
  if(ca.created){
    self.createKey(name, utils.cC(callback,function(){
      self.createCert(name, ca, utils.cC(callback,function(){
        var pair = self._keyPair(name, true);
        pair.created = true;
        callback(null, pair);
      }));
    }));
  } else {
    self.checkCreateKey(name, utils.cC(callback, function(existed){
      self.checkCreateCert(name, ca, !existed, utils.cC(callback, function(certExisted){
        var pair = self._keyPair(name, true);
        pair.created = !(existed && certExisted);
        callback(null, pair);
      }));
    }));
  }
}

/**
 * Function creating folder structure for key
 * 
 * @param name {String}  name of key
 * @param callback {Function}
 */
function _createPath(name, callback){
  var parts = name.split(path.sep);
  parts.pop();
  var fullPath = parts.join(path.sep);
  mkdirp(fullPath, callback);
}

/**
 * Function creating subject name for -subj
 * 
 * @param name {String}  name of key
 */
function _subjectName(name){
  return name.replace(/\//g,'_') + '-' + Date.now();
}