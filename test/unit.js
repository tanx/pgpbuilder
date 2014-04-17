'use strict';

require.config({
    baseUrl: '.',
    paths: {
        'chai': '../node_modules/chai/chai',
        'sinon': '../node_modules/sinon/pkg/sinon',
        'mailbuild': '../node_modules/mailbuild/src/mailbuild',
        'addressparser': '../node_modules/mailbuild/node_modules/addressparser/src/addressparser',
        'mimefuncs': '../node_modules/mailbuild/node_modules/mimefuncs/src/mimefuncs',
        'mimetypes': '../node_modules/mailbuild/node_modules/mimetypes/src/mimetypes',
        'punycode': '../node_modules/mailbuild/node_modules/punycode/punycode',
        'stringencoding': '../node_modules/stringencoding/dist/stringencoding',
        'openpgp': 'lib/openpgp.min',
        'crypto': 'lib/dummy' // this is due to the fact how requirejs parses modules (there is a require(crypto) in the function)
    },
    shim: {
        'sinon': {
            exports: 'sinon'
        }
    }
});

mocha.setup('bdd');
require(['unit-test', 'integration-test'], function() {
    (window.mochaPhantomJS || window.mocha).run();
});