/* 
 * Copyright 2012 Karl Düüna <karl.dyyna@gmail.com> All rights reserved.
 */
'use strict';

var ssl = require('../index');
var vows = require('vows');
var assert = require('assert');
var fs = require('fs');
var path = require('path');
var rimraf = require('rimraf');
var spec = require('vows/lib/vows/reporters/spec');
var foldermap = require('foldermap');

function _findCWD(module){
  try{
    var stats = fs.statSync('./node_modules/' + module);
    return process.cwd();
  } catch(e){
    var lvl = 1;
    var folderPath = '../' + module;
    while(lvl < 10){
      try{
        var stats = fs.statSync(folderPath);
        var folderMapCWD = process.cwd() + path.sep;
        for(var i = 0; i < lvl; i++){
          folderMapCWD += '..' + path.sep;
        }
        return path.resolve(folderMapCWD);
      } catch(e){
        folderPath = '..' + path.sep + '..' + path.sep + folderPath;
        lvl = lvl + 2;
      }
    }
  }
  return process.cwd();
}

var enumerableClone = function(o){
  var keys = Object.getOwnPropertyNames(o);
  var t = {};
  for(var i in keys){
    if(typeof o[keys[i]] === 'object' && o[keys[i]].length === undefined ){
      t[keys[i]] = enumerableClone(o[keys[i]]);
      continue;
    }
    t[keys[i]] = o[keys[i]];
  }
  return t;
}

// Will test own properties only
function deepEqualWithDiff(a, e, names){
  var dif = {};
  var aKeys = Object.keys(a);
  var eKeys = Object.keys(e);

  var cKeys = aKeys;
  var dKeys = eKeys;
  var c = a;
  var d = e;
  var names = {
    c: names ? names['a'] : 'Actual',
    d: names ? names['e'] : 'Expected'
  }

  if(eKeys.length > aKeys.length){
    cKeys = eKeys;
    dKeys = aKeys;
    c = e;
    d = a;
    names = {
      d: names ? names['a'] : 'Actual',
      c: names ? names['e'] : 'Expected'
    }
  }


  for(var i = 0, co = cKeys.length; i < co; i++){
    var key = cKeys[i];
    if(typeof c[key] !== typeof d[key]){
      dif[key] = 'Type mismatch ' + names['c'] + ':' + typeof c[key] + '!==' + names['d'] + typeof d[key];
      continue;
    }
    if(typeof c[key] === 'function'){
      if(c[key].toString() !== d[key].toString()){
        dif[key] = 'Differing functions';
      }
      continue;
    }
    if(typeof c[key] === 'object'){
      if(c[key].length !== undefined){ // array
        var temp = c[key].slice(0);
        temp = temp.filter(function(el){
          return (d[key].indexOf(el) === -1);
        });
        var message = '';
        if(temp.length > 0){
          message += names['c'] + ' excess ' + JSON.stringify(temp);
        }

        temp = d[key].slice(0);
        temp = temp.filter(function(el){
          return (c[key].indexOf(el) === -1);
        });
        if(temp.length > 0){
          message += ' and ' + names['d'] + ' excess ' + JSON.stringify(temp);
        }
        if(message !== ''){
          dif[key] = message;
        }
        continue;
      }
      var diff = deepEqualWithDiff(c[key], d[key], {a:names['c'],e:names['d']});
      if(diff !== true && Object.keys(diff).length > 0){
        dif[key] = diff;
      }
      continue;
    }
    // Simple types left so
    if(c[key] !== d[key]){
      dif[key] = names['c'] + ':' + c[key] + ' !== ' + names['d'] + ':' + d[key]; 
    }
  }
  return Object.keys(dif).length > 0 ? dif : true;
}

var keyChain = require('../index').createKeyChain({root:process.cwd() + path.sep + 'test'});
var keyChainO = require('../index').createKeyChain({
  root:process.cwd() + path.sep + 'test',
  ns:[
    {
      clear: true,
      create: false,
      force: false,
      required: false,
      folder: 'agents',
      name: 'agent'
    },
    {
      clear: false,
      required: true,
      folder: 'main',
      name: 'root'
    },
    {
      type:'ca',
      clear: true,
      create: true,
      folder: 'ca',
      name: 'ca'
    },
    {
      type:'crt',
      clear: true,
      create: true,
      ca:'ca',
      folder: 'sec',
      name: 'sec'
    },
    {
      type:'csr',
      clear: true,
      create: true,
      ca:'ca',
      folder: 'testA',
      name: 'testA'
    }
  ]
});

var map = foldermap.mapTreeSync(process.cwd()+path.sep+'test'+path.sep+'certs');
map = enumerableClone(map);
delete map['incoming'];
// Create a Test Suite
vows.describe('SSL-KeyChain').addBatch({
  'KeyGen':{
    topic: function(){
      console.log('Testing ssl-keygen');
      require('child_process').exec('npm test ssl-keygen', {cwd: _findCWD('ssl-keygen') }, this.callback);
    },
    'keygen working':function(err, stdout, stderr){
      assert.equal(err, null);
      assert.equal(stderr, '');
    }
  }
}).addBatch({
  'KeyChain - noconf init':{
    topic:function(){
      keyChain.init(this.callback);
    },
    'without error':function(err){
      assert.equal(err, null);
    },
    'has map':function(){
      assert.isObject(keyChain.certs);
    },
    'map is correct':function(){
      var temp = enumerableClone(keyChain.certs);
      var dif = deepEqualWithDiff(map, temp);
      if(dif !== true){
        console.log(dif);
      }
      assert.strictEqual(dif, true);
    }
  }
}).addBatch({
  'KeyChain - init with options':{
    topic:function(){
      keyChainO.init(this.callback)
    },
    'no error':function(err){
      assert.equal(err, null);
    },
    'has map':function(){
      assert.isObject(keyChainO.certs);
    },
    'has main keys':function(){
      assert.isObject(keyChainO.certs.root.key);
      assert.isObject(keyChainO.certs.root.crt);
    },
    'agents deleted':function(){
      assert.isObject(keyChainO.certs.agent);
      assert.deepEqual({}, keyChainO.certs.agent);
    },
    'ca created':function(){
      assert.isObject(keyChainO.certs.ca);
      assert.isObject(keyChainO.certs.ca.key);
      assert.isObject(keyChainO.certs.ca.crt);
    },
    'sec created':function(){
      assert.isObject(keyChainO.certs.sec);
      assert.isObject(keyChainO.certs.sec.key);
      assert.isObject(keyChainO.certs.sec.crt);
      assert.isObject(keyChainO.certs.sec.csr);
    },
    'testA created':function(){
      assert.isObject(keyChainO.certs.testA);
      assert.isObject(keyChainO.certs.testA.key);
      assert.isObject(keyChainO.certs.testA.csr);
    }
  }
}).addBatch({
  'KeyChain - recieve file':{
    topic:function(){
      keyChainO.receiveFile('test.csr','Hello', 'incoming', false, this.callback);
    },
    'file on disk':function(err, map){
      assert.isNull(err);
      var stats = fs.statSync(process.cwd()+path.sep+'test'+path.sep+'certs'+path.sep+keyChainO.incoming+'test.csr');
    },
    'in added':function(){
      assert.isObject(keyChainO.added['test.csr']);
    },
    'right content':function(){
      assert.equal('Hello',keyChainO.added['test.csr']._content);
    }
  }
}).addBatch({
  'KeyChain - sign Request':{
    topic:function(){
      keyChainO.signRequest(keyChainO.certs.testA.csr._content, 'ca', this.callback);
    },
    'returns map':function(err, map){
      assert.isNull(err);
      assert.isObject(map);
    },
    'in added':function(err, map){
      assert.isObject(keyChainO.added[map._base + '.csr']);
      assert.isObject(keyChainO.added[map._base + '.crt']);
    }
  }
}).run({reporter:spec});