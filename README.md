[ssl-keychain](https://github.com/DeadAlready/node-ssl-keychain) is a wrapper for manipulating SSL certs.

# Installation

    $ npm install ssl-keychain

# Usage

ssl-keychain loads and creates SSL certificates from designated folder based on configuration, 
allowing easy manipulation and access to certs.

## API

The module exports the following functions and objects

+ KeyChain: *Handle to the KeyChain constructor function
+ KeyGen: *Handle to the underlying ssl-keygen module
+ createKeyChain(options): *function returning a new ssl-keychain with specified options
+ createKeyGen(options): *function returning a new ssl-keygen with specified options


### KeyChain Options

The following options are available:

+ root: *Project root folder will default to process.cwd()
+ folder: *The certs folder name default to 'certs'
+ incoming: *The folder where incoming certs are stored defaults to 'incoming'
+ clearIncoming: *Wheter to delete incoming folder upon startup, default true
+ sync: *Wheter to map folders synchronously
+ ns: *Array of certificate descriptor objects

#### Certificate descriptions

Each certificate can be described with the following properties

+ type: *Type of the certificate - can be 'ca', 'csr' or 'crt'
+ ca: *CA to use when signing cert
+ clear: *Wheter to delete previous certs, default false
+ create: *Wheter to create certs if missing, default false
+ force: *Wheter to force create certs, default false
+ required: *Wheter to raise an error if missing, default false
+ folder: *Folder where certs should be, default ''
+ name: *Name of certs

There are two ways of specifying the options:

## KeyChain API

The following functions are exported to the KeyChain object

### checkAllFiles

Function for checking all definitions in the KeyChain

 * @param {Boolean} [dontCreate=false] whether to stop creation of keys
 * @param {Boolean} [noErrors=false] whether to supress errors
 * @param {Function} callback

### clearFolders

Function for deleting marked folders

 * @param {Function} callback

### createKeyObject

Function for creating key object

 * @param {Object} info certInfo object
 * @param {Function} callback

### createMeta

Function for creating easy access methods to configured certs

### init

Function for initializing the KeyChain

 * @param {Boolean} [dontCreate=false] whether to stop creation of keys
 * @param {Boolean} [noErrors=false] whether to supress errors
 * @param {Function} callback

### mapFolderSync

Function for mapping existing keys synchronously

### receiveFile

Function for writing a file into filesystem

 * @param {String}  name name of the file
 * @param {String}  file file contents
 * @param {String}  [info='incoming'] the name of certInfo object to add under
 * @param {Boolean} [force=false] whether to overwrite if exists
 * @param {Function}

### signRequest

Function for receiving a csr and signing it

 * @param {String}  utf8 string with csr contents
 * @param {String|Object}  ca name of ca or ca object to use
 * @param {Function} callback

## License

The MIT License (MIT)
Copyright (c) 2012 Karl Düüna

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.