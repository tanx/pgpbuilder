'use strict';

require.config({
    paths: {
        'chai': '../node_modules/chai/chai',
        'sinon': '../node_modules/sinon/pkg/sinon',
        'emailjs-mime-builder': '../node_modules/emailjs-mime-builder/src/emailjs-mime-builder',
        'emailjs-addressparser': '../node_modules/emailjs-mime-builder/node_modules/emailjs-addressparser/src/emailjs-addressparser',
        'emailjs-mime-codec': '../node_modules/emailjs-mime-builder/node_modules/emailjs-mime-codec/src/emailjs-mime-codec',
        'emailjs-mime-types': '../node_modules/emailjs-mime-builder/node_modules/emailjs-mime-types/src/emailjs-mime-types',
        'punycode': '../node_modules/emailjs-mime-builder/node_modules/punycode/punycode',
        'emailjs-stringencoding': '../node_modules/emailjs-mime-builder/node_modules/emailjs-mime-codec/node_modules/emailjs-stringencoding/src/emailjs-stringencoding',
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