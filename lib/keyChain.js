/* 
 * Copyright 2012 Karl Düüna <karl.dyyna@gmail.com> All rights reserved.
 */
'use strict';

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var mkdirp = require('mkdirp');
var rimraf = require('rimraf');

var foldermap = require('foldermap');
var KeyGen = require('ssl-keygen');

var utils = require('./utils');

function KeyChain(options){
  if(this instanceof KeyChain === false){
    return new KeyChain(options);
  }
  
  if(!options){
    options = {};
  }
  
  // Give possibility to include bunyan logger
  if( options.log === true) {
    this.log = function(type, log){
      console.log(log);
    }
  } else if (typeof options.log === 'object'){
    this.log = function(type, log){
      options.log[type](log);
    }
  } else {
    this.log = function(){}
  }
  
  options.root = utils.fixPath(options.root || process.cwd());
  options.folder = options.folder || 'certs';
  
  this.root = options.root;
  this.folder = options.folder;
  this.incoming = utils.fixPath(options.incoming || 'incoming');
  this.clearIncoming = options.incoming !== undefined ? options.incoming : true;
  
  try{
    fs.statSync(utils.fixPath(this.root) + utils.fixPath(this.folder));
  } catch(e){
    mkdirp.sync(utils.fixPath(this.root) + utils.fixPath(this.folder));
  }
    
  var def = {
    type: 'crt',
    ca: false,
    clear: false,
    create: false,
    force: false,
    required: false,
    folder: '',
    name: ''
  }
  
  this.certInfo = {};
  var self = this;
  
  if(options.ns && typeof options.ns === 'object' && options.ns.length){
    options.ns.forEach(function(el){
      if(typeof el === 'string'){
        self.certInfo[el] = utils.extend(def, {name: el, folder:el});
      } else if(typeof el === 'object' && el.name){
        self.certInfo[el.name] = utils.extend(def, el);
      }
//      self.certInfo[el.name].folder = utils.fixPath(self.certInfo[el.name].folder);
    });
  }
  
  this._default = options._default || false;
  
  this.certs = {};
  this.created = [];
  
  this.added = {};
  
  this.keyGen = KeyGen.createKeyGen(options);
  
  Object.defineProperty(self, '_cC',{value: utils.wrapCleanCallback(self)});
  
  if(options.sync){
    this.mapFolderSync();
    this.createMeta();
  }
  
}
module.exports = KeyChain;

/**
 * Function for initializing the KeyChain
 * 
 * @param {Boolean} [dontCreate=false] whether to stop creation of keys
 * @param {Boolean} [noErrors=false] whether to supress errors
 * @param {Function} callback
 */
KeyChain.prototype.init = function(dontCreate, noErrors, callback){
  this.log('debug','init');
  
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
    foldermap.map(self.root + self.folder, self._cC(callback, function(map){
      self[self.folder] = map;
      self.checkAllFiles(dontCreate, noErrors, self._cC(callback, function(){
        self.createMeta();
        callback();
      }));
    }));
  });
}

/**
 * Function for mapping existing keys in synchronously
 */
KeyChain.prototype.mapFolderSync = function(){
  this.log('debug','mapFolderSync');
  var self = this;
  
  self._map = foldermap.mapSync(utils.fixPath(self.root) + self.folder);
  self.certs = {};
  for(var i in self.certInfo){
    self.certs[i] = {};
    ['key','crt','csr'].forEach(function(el){
      var tmp = self._getFileInfo(self.certInfo[i], el);
      if(tmp){
        self.certs[i][el] = tmp;
      }
    });
  }
}
/**
 * Function for creating easy access methods
 */
KeyChain.prototype.createMeta = function(){
  this.log('debug','createMeta');
  var self = this;
  for(var i in self.certs){
    for(var s in self.certs[i]){
      (function(i,s){
        Object.defineProperty(self, i + utils.capitalize(s), {get:function(){ return self.certs[i][s]._content; }});
      })(i,s);
    }
  }
}

/**
 * Function for creating specific map of keys
 * 
 * @param {Function} callback
 * @param {Array} [created=[]] array of created cert infos
 */
KeyChain.prototype._reMap = function(callback, created){
  this.log('debug','_reMap');
  var self = this;
  created = created || [];
  
  foldermap.map(utils.fixPath(self.root) + self.folder, self._cC(callback, function(map){
    self._map = map;
    self.certs = {};
    for(var i in self.certInfo){
      self.certs[i] = {};
      ['key','crt','csr'].forEach(function(el){
        var tmp = self._getFileInfo(self.certInfo[i], el);
        if(tmp){
          self.certs[i][el] = tmp;
        }
      });
    }
    for(var i in created){
      for(var s in self.certs[created[i].name]){
        (function(s,i){
          Object.defineProperty(self.certs[created[i].name][s], '_created', {value:true});
        })(s,i)
      }
    }
    callback();
  }));
}

/**
 * Function for getting specific file info from map
 * 
 * @param {Object} info certInfo
 * @param {String} type type of file
 * @return {Object|Boolean} object or boolean false
 */
KeyChain.prototype._getFileInfo = function(info, type){
  this.log('debug','_getFileInfo');
  
  var self = this;
  if(info.folder !== ''){
    if(self._map[info.folder] && self._map[info.folder][info.name + '.' + type]){
      return self._map[info.folder][info.name + '.' + type];
    } else {
      return false;
    }
  } else {
    if(self._map[info.name + '.' + type]){
      return self._map[info.name + '.' + type];
    } else {
      return false;
    }
  }
}

/**
 * Function for checking all definitions in the KeyChain
 * 
 * @param {Boolean} [dontCreate=false] whether to stop creation of keys
 * @param {Boolean} [noErrors=false] whether to supress errors
 * @param {Function} callback
 */
KeyChain.prototype.checkAllFiles = function(dontCreate, noErrors, callback){
  this.log('debug','checkAllFiles');
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
    self.checkFiles(map, info);
  }
  
  if(!noErrors && errors.length){
    errors.forEach(function(err){
      self.log('error', err);
    });
    throw new Error('Missing files');
  } else if(errors.length){
    self.log('debug','Returning errors');
    return callback(errors);
  } else if(dontCreate){
    self.log('debug','Returning _reMap');
    return self._reMap(callback);
  }
  
  var count = create.length;
  if(count === 0){
    self.log('debug','Nothing to create');
    return self._reMap(callback);
  }
  
  var createCA = [];
  var createKey = [];
  create.forEach(function(info){
    if(info.type === 'ca'){
      createCA.push(info);
    } else {
      createKey.push(info);
    }
  });
  
  self._tmp = {};
  self.log('debug','Create CA-s');
  self._createObjects(createCA, self._cC(callback, function(){
    self.log('debug','create KEYs');
    self._createObjects(createKey, self._cC(callback, function(){
      self._reMap(callback, create);
    }));
  }));
}

/**
 * Function for creating objects in array
 * 
 * @param {Array} arr array of info objects for certs to create
 * @param {Function} callback
 */
KeyChain.prototype._createObjects = function(arr, callback){
  this.log('debug','_createObjects');
  var self = this;
  var errors = [];
  var count = arr.length;
  
  if(arr.length === 0){
    callback();
  }
  
  arr.forEach(function(info){
    self.createKeyObject(info, function(err, keys){
      if(err){
        errors.push(err);
      }
      console.log('here');
      self._tmp[info.name] = keys;
      if(--count === 0){
        if(errors.length){
          callback(errors);
          return;
        } else {
          callback();
        }
      }
    });
  });
}

/**
 * Function for checking the map for keys
 * 
 * @param {Object} map map of keys and certs
 * @param {Object} info object containing info about keypair
 * @return {Array} containing errors
 */
KeyChain.prototype.checkFiles = function(map, info){
  this.log('debug','checkFiles');
  var self = this;
  var errors = [];
  if(info.folder === ''){
    if(!map[info.name + '.key']){
      errors.push(new Error(self._getFilePath(info.name,'key') + ' missing'));
    }
    if(!map[info.name + '.crt']){
      errors.push(new Error(self._getFilePath(info.name,'crt') + ' missing'));
    }
  } else {
    if(!(map[info.folder] && map[info.folder][info.name + '.key'])){
      errors.push(new Error(self._getFilePath(info.name,'key') + ' missing'));
    }
    if(!(map[info.folder] && map[info.folder][info.name + '.crt'])){
      errors.push(new Error(self._getFilePath(info.name,'crt') + ' missing'));
    }
  }
  return errors;
}

/**
 * Function for getting the file path based on name and type
 * 
 * @param {Boolean} name name of certInfo
 * @param {Boolean} type filetype
 * @return {String}
 */
KeyChain.prototype._getFilePath = function(name, type){
  this.log('debug','_getFilePath');
  return this.root + utils.fixPath(this.folder) + utils.fixPath(this.certInfo[name].folder || '') + name + '.' + type;
}

/**
 * Function for deleting marked folders
 * 
 * @param {Function} callback
 */
KeyChain.prototype.clearFolders = function(callback){
  this.log('debug','clearFolders');
  var self = this;
  var clear = [];
  // Map folders to delete
  for(var i in self.certInfo){
    if(self.certInfo[i].clear){
      clear.push(utils.fixPath(self.root) + utils.fixPath(self.folder) + self.certInfo[i].folder);
    }
  }
  if(self.clearIncoming){
    clear.push(utils.fixPath(self.root) + utils.fixPath(self.folder) + self.incoming);
  }
  // Delete folders
  var count = clear.length;
  if(count === 0){
    callback();
    return;
  }
  clear.forEach(function(el){
    rimraf(el, function(){
      if(--count === 0){
        callback();
      }
    });
  });
}

/**
 * Function for creating key object
 * 
 * @param {Object} info certInfo object
 * @param {Function} callback
 */
KeyChain.prototype.createKeyObject = function(info, callback){
  this.log('debug','_createKeyObject');
  var self = this;
  switch(info.type){
    case 'crt':
      var ca = self.certInfo[info.ca];
      if(!ca){
        callback(new Error('Missing CA - ' + info.ca));
        return;
      }
      if(ca.create && !self._tmp[info.ca]){
        callback(new Error('Missing created CA - ' + info.ca));
        return;
      } 
      ca = self._tmp[info.ca] || self._getKeyPair(ca);
      
      self.keyGen.createSelfSigned(self._getName(info), ca, (info.force || ca.key._created), callback);
      
      break;
    case 'ca':
      self.keyGen.createCA(self._getName(info), info.force, callback);
      break;
    case 'csr':
      self.keyGen.createKey(self._getName(info), info.force, self._cC(callback, function(){
        self.keyGen.createSignRequest(self._getName(info), callback)
      }));
      break;
  }
}

/**
 * Function for extracting keyPair info from map
 * 
 * @param {Object} info certInfo object
 * @return {Object}
 */
KeyChain.prototype._getKeyPair = function(info){
  this.log('debug','_getKeyPair');
  var self = this;
  if(info.folder !==''){
    return {
      key:self[self.folder][info.folder][info.name + '.key'],
      crt:self[self.folder][info.folder][info.name + '.crt']
    }
  } else {
    return {
      key:self[self.folder][info.name + '.key'],
      crt:self[self.folder][info.name + '.crt']
    }
  }
}

/**
 * Function for getting the relative name of key
 * 
 * @param {Object} info certInfo object
 * @return {String}
 */
KeyChain.prototype._getName = function(info){
  return utils.fixPath(info.folder) + info.name;
}

/**
 * Function for getting the cert name from cert object
 * 
 * @param {Object} cert req.connection.getPeerCertificate
 */
KeyChain.prototype._getCertName = function getCertName(cert){
  this.log('debug','_getCertName');
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
 * Function for writing a file into filesystem
 * 
 * @param {String}  name name of the file
 * @param {String}  file file contents
 * @param {String}  [info='incoming'] the name of certInfo object to add under
 * @param {Boolean} [force=false] whether to overwrite if exists
 * @param {Function}
 */
KeyChain.prototype.receiveFile = function receiveFile(name, file, info, force, callback){
  this.log('debug','receiveFile');
  if(info instanceof Function){
    callback = info;
    force = false;
    info = 'incoming';
  } else if(typeof info === 'boolean'){
    callback = force;
    force = info;
    info = 'incoming';
  }else if(force instanceof Function){
    callback = force;
    force = false;
  }
  
  var self = this;
  var filePath = self._getIncomingFilePath(name, info);
  mkdirp(path.dirname(filePath), function(){
    fs.stat(filePath, function(err, stat){
      if(err || force){
        fs.writeFile(filePath, file, self._cC(callback, function(){
          self._returnMap(callback, name, true, info);
        }));
      } else {
        self._returnMap(callback, name, false, info)
      }
    });
  });
  
}

/**
 * Function for getting the file path of incoming file
 * 
 * @param {String} name name of file
 * @param {String} name of info object to add under
 * @return {String}
 */
KeyChain.prototype._getIncomingFilePath = function(name, info){
  this.log('debug','_getIncomingFilePath');
  if(info === 'incoming' || !this.certInfo[info]){
    return this.root + utils.fixPath(this.folder) + utils.fixPath(this.incoming) + name;
  }
  return this.root + utils.fixPath(this.folder) + utils.fixPath(this.certInfo[info].folder) + name;
}

/**
 * Function for receiving a csr and signing it
 * 
 * @param {String}  utf8 string with csr contents
 * @param {String|Object}  ca name of ca or ca object to use
 * @param {Function} callback
 */
KeyChain.prototype.signRequest = function signRequest(file, ca, callback){
  this.log('debug','signRequest');
  var self = this;
  if(typeof ca === 'string'){
    ca = self.certs[ca];
  }
  var name = self._getCertName();
  var fullName = name + '.csr';
  self.receiveFile(fullName, file, 'incoming', true, self._cC(callback, function(map){
    self.keyGen.signRequest('incoming' + path.sep + name, ca, true, self._cC(callback, function(crt){
      self.added[name + '.crt'] = crt;
      callback(null, crt);
    }));
  }));
}

/**
 * Function for returning the corresponding map object
 * 
 * @param {Function} callback
 * @param {String} name name of the cert
 * @param {Boolean} created whether or not the cert was created
 * @param {String} info name of the info object
 */
KeyChain.prototype._returnMap = function _returnMap(callback, name, created, info){
  this.log('debug','_returnMap');
  var self = this;
  
  foldermap.map(self._getIncomingFilePath(name, info), function(err, map){
    Object.defineProperty(map, '_created', {value: created});
    
    self.added[name] = map;
    if(info !== 'incoming'){
      if(!self.certs[info][name]){
        self.certs[info][name] = {};
      }
      self.certs[info][name][path.extname(name).substr(1)] = map;
    }
    callback(null, map);
  });
}