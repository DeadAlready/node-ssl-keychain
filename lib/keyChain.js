'use strict';

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var mkdirp = require('mkdirp');
var rimraf = require('rimraf');

var foldermap = require('foldermap');

var utils = require('./utils');
var KeyGen = require('./keyGen');

function KeyChain(options){
  if(this instanceof KeyChain === false){
    return new KeyChain(options);
  }
  
  if(!options){
    options = {};
  }
  
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
  
  options.root = utils.fixPath(options.root || process.cwd());
  options.folder = options.folder || 'certs';
  
  this.root = options.root;
  this.folder = options.folder;
    
  var def = {
    type: 'crt',
    clear: true,
    create: false,
    force: false,
    required: false,
    folder: '',
    name: ''
  }
  
  this.certInfo = {};
  
  if(options.ns && typeof options.ns === 'object' && options.ns.length){
    options.ns.forEach(function(el){
      if(typeof el === 'string'){
        this.certInfo[el] = utils.extend(def, {name: el, folder:el});
      } else if(typeof el === 'object' && el.name){
        this.certInfo[el.name] = utils.extend(def, el);
      }
      this.certInfo[el.name].folder = utils.fixPath(this.certInfo[el.name].folder);
    });
  }
  
  this.certs = {};
  this.created = [];
  
  this.added = {};
  
  this.keyGen = new KeyGen(options);
  
  if(options.sync){
    this.mapFolderSync();
  }
  
}
module.exports = KeyChain;

KeyChain.prototype.init = function(dontCreate, noErrors, callback){
  if(dontCreate instanceof Function){
    callback = dontCreate;
    dontCreate = false;
    noErrors = false;
  } else if(noErrors instanceof Function){
    callback = noErrors;
    noErrors = false;
  }
  
  var self = this;
  self.clearFolders(function(){
    foldermap.mapTree(self.root + self.folder, utils.cC(callback, function(map){
      self[self.folder] = map;
      self.checkAllFiles(dontCreate, noErrors, utils.cC(callback, function(){

      }));
    }));
  });
}

KeyChain.prototype.checkAllFiles = function(dontCreate, noErrors, callback){
  
  if(dontCreate instanceof Function){
    callback = dontCreate;
    dontCreate = false;
    noErrors = false;
  } else if(noErrors instanceof Function){
    callback = noErrors;
    noErrors = false;
  }
  if(!callback){
    callback = function(){ return arguments; }
  }
  
  var self = this;
  var errors = [];
  var create = [];
  
  var map = self[self.folder];
  // Check required files
  for(var i in self.certInfo){
    var info = self.certInfo[i];
    if(info.required){
      errors = errors.concat(self.checkFiles(map, info));
      continue;
    }
    if(info.create){
      if(self.checkFiles(map, info).length > 0){
        create.push(info);
      }
      continue;
    }
  }
  
  if(!noErrors){
    errors.forEach(function(err){
      self.log('error',err);
    });
    throw new Error('Missing files');
  } else if(errors.length){
    return callback(errors);
  } else if(dontCreate){
    return callback(null, create);
  }
  
  var count = create.count;
  if(count === 0){
    return callback();
  }
  
  create.forEach(function(info){
    self.createKeyObject(info, function(err){
      if(err){
        errors.push(err);
      }
      if(--count === 0){
        callback(errors.length ? errors : null, create);
      }
    });
  });
}

KeyChain.prototype.checkFiles = function(map, info){
  var self = this;
  var errors = [];
  if(info.folder === ''){
    if(!map[info.name + '.key']){
      errors.push(new Error(self._getFilePath(i,'key') + ' missing'));
    }
    if(!map[info.name + '.crt']){
      errors.push(new Error(self._getFilePath(i,'crt') + ' missing'));
    }
  } else {
    if(!map[info.folder][info.name + '.key']){
      errors.push(new Error(self._getFilePath(i,'key') + ' missing'));
    }
    if(!map[info.folder][info.name + '.crt']){
      errors.push(new Error(self._getFilePath(i,'crt') + ' missing'));
    }
  }
  return errors;
}

KeyChain.prototype._getFilePath = function(name, type){
  return this.root + utils.fixPath(this.folder) + utils.fixPath(this.certInfo[name].folder) + name + '.' + type;
}

KeyChain.prototype.clearFolders = function(callback){
  var self = this;
  var clear = [];
  // Map folders to delete
  for(var i in self.certInfo){
    if(self.certInfo[i].clear){
      clear.push(self.folder + self.certInfo[i].folder);
    }
  }
  // Delete folders
  var count = clear.length;
  clear.forEach(function(el){
    rimraf(el, function(){
      if(--count === 0){
        callback();
      }
    });
  });
}

KeyChain.prototype.createMeta = function(str, map){
  var self = this;
  if(!map){
    map = self[self.folder];
  }
  
  for(var i in map){
    (function(i){
      if(map[i]._type === 'file'){
        Object.defineProperty(self[self.folder],
          str + utils.capitalize(map[i]._base) + utils.capitalize(map[i]._ext),
          { 
            get: function(){ 
              return fs.readFileSync(map[i]._path,'utf8'); 
            }
          });
      } else {
        str = str === '' ? map[i]._name : str + utils.capitalize(map[i]._name);
        self.createMeta(str, map[i]);
      }
    })(i)
  }
  
}

/**
 * Function for getting the cert name from cert object
 * 
 * @param cert  {Object}  req.connection.getPeerCertificate
 */
KeyChain.prototype._getCertName = function getCertName(cert){
  if(cert){
    return crypto.createHash('sha1')
      .update(cert.fingerprint)
      .digest('hex');
  }
  return crypto.createHash('sha1')
    .update(Date.now() + ' ' + Math.random())
    .digest('hex');
}

/**
 * Function for writing CA cert into filesystem
 * 
 * @param name      {String}  name of the key
 * @param key       {String}  key itself
 * @param callback {Function}
 */
KeyChain.prototype.receiveFile = function receiveFile(name, type, file, callback){
  var pair = this.keyGen._keyPair(name, true);
  
  fs.writeFile(pair[type], file, function(err){
    callback(err, pair[type]);
  });
}

/**
 * Function for returning the file name without extension or path
 * 
 * @param fullName  {String}  full file path
 */
KeyChain.prototype._getName = function getName(fullName){
  var file = fullName.split(path.sep).pop();
  var chunks = file.split('.');
  chunks.pop();
  return chunks.join('.');
}

/**
 * Function for receiving a CA to the list
 * 
 * @param file  {String}  utf8 string with cert contents
 * @param cert  {Object}  req.connection.getPeerCertificate
 * @param callback  {Function}
 */
KeyChain.prototype.addCA = function addCA(file, name, callback){
  var self = this;
  mkdirp(self.folder + self.caFolder, utils.cC(callback,function(){
    self.receiveFile(self.caFolder + name, 'crt', file, function(err, fullName){
      if(!self[self.caFolderName]){
        self[self.caFolderName] = {};
      }
      self[self.caFolderName][name] = {
        location: fullName
      };
      callback(err, {name:name,location:fullName});
    });
  }));
}

/**
 * Function for receiving a CA to the list
 * 
 * @param file  {String}  utf8 string with cert contents
 * @param cert  {Object}  req.connection.getPeerCertificate
 * @param callback  {Function}
 */
KeyChain.prototype.signAgentRequest = function signAgentRequest(file, callback){
  var self = this;
  var name = self._getCertName();
  mkdirp(self.folder + self.agentFolder, utils.cC(callback,function(){
    self.receiveFile(self.agentFolder + name, 'csr', file, function(err, fullName){
      self.keyGen.signRequest(self.agentFolder + name, self.ca, utils.cC(callback,function(){
        fs.readFile(fullName,'utf8',utils.cC(callback,function(cert){
          if(!self[self.agentFolderName]){
            self[self.agentFolderName] = {};
          }
          self[self.agentFolderName][name] = {
            location: fullName
          };
          callback(null, {name:name,location:fullName,cert:cert});
        }));
      }));
    });
  }));
}