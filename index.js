/* 
 * Copyright 2012 Karl Düüna <karl.dyyna@gmail.com> All rights reserved.
 */
'use strict';

var KeyChain = require('./lib/keyChain');
var KeyGen = require('ssl-keygen');

module.exports.KeyChain = KeyChain;
module.exports.KeyGen = KeyGen;

module.exports.createKeyChain = function(options){
  return new KeyChain(options);
}

module.exports.createKeyGen = function(options){
  return new KeyGen(options);
}

