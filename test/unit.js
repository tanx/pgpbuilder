'use strict';

require.config({
    paths: {
        'chai': '../node_modules/chai/chai',
        'sinon': '../node_modules/sinon/pkg/sinon',
        'mailbuild': '../node_modules/mailbuild/src/mailbuild',
        'wo-addressparser': '../node_modules/mailbuild/node_modules/wo-addressparser/src/addressparser',
        'mimefuncs': '../node_modules/mailbuild/node_modules/mimefuncs/src/mimefuncs',
        'mimetypes': '../node_modules/mailbuild/node_modules/mimetypes/src/mimetypes',
        'punycode': '../node_modules/mailbuild/node_modules/punycode/punycode',
        'wo-stringencoding': '../node_modules/mailbuild/node_modules/mimefuncs/node_modules/wo-stringencoding/dist/stringencoding',
        'openpgp': 'lib/openpgp.min',
        'crypto': 'lib/dummy' // this is due to the fact how requirejs parses modules as text, even though it may never reach the require (there is a require(crypto) in the function)
    },
    shim: {
        'sinon': {
            exports: 'sinon'
        }
    }
});

mocha.setup('bdd');
require(['unit-test'], function() {
    (window.mochaPhantomJS || window.mocha).run();
});