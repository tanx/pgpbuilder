// 'use strict';

// if (typeof module === 'object' && typeof define !== 'function') {
//     var define = function(factory) {
//         module.exports = factory(require, exports, module);
//     };
// }

// define(function(require) {
//     var chai = require('chai'),
//         expect = chai.expect,
//         PgpBuilder = require('../src/pgpbuilder'),
//         openpgp = require('openpgp'),
//         MailParser = require('mailparser').MailParser;

//     chai.Assertion.includeStack = true;

//     describe('integration tests', function() {
//         var pgpbuilder, pubkeyArmored;

//         beforeEach(function(done) {
//             var opts, privKey;

//             opts = {
//                 pgpWorkerPath: 'lib/openpgp.worker.js'
//             };

//             privKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n' +
//                 'Version: OpenPGP.js v.1.20131116\r\n' +
//                 'Comment: Whiteout Mail - http://whiteout.io\r\n' +
//                 '\r\n' +
//                 'xcL+BFKODs4BB/9iOF4THsjQMY+WEpT7ShgKxj4bHzRRaQkqczS4nZvP0U3g\r\n' +
//                 'qeqCnbpagyeKXA+bhWFQW4GmXtgAoeD5PXs6AZYrw3tWNxLKu2Oe6Tp9K/XI\r\n' +
//                 'xTMQ2wl4qZKDXHvuPsJ7cmgaWqpPyXtxA4zHHS3WrkI/6VzHAcI/y6x4szSB\r\n' +
//                 'KgSuhI3hjh3s7TybUC1U6AfoQGx/S7e3WwlCOrK8GTClirN/2mCPRC5wuIft\r\n' +
//                 'nkoMfA6jK8d2OPrJ63shy5cgwHOjQg/xuk46dNS7tkvGmbaa+X0PgqSKB+Hf\r\n' +
//                 'YPPNS/ylg911DH9qa8BqYU2QpNh9jUKXSF+HbaOM+plWkCSAL7czV+R3ABEB\r\n' +
//                 'AAH+AwMI8l5bp5J/xgpguvHaT2pX/6D8eU4dvODsvYE9Y4Clj0Nvm2nu4VML\r\n' +
//                 'niNb8qpzCXXfFqi1FWGrZ2msClxA1eiXfk2IEe5iAiY3a+FplTevBn6rkAMw\r\n' +
//                 'ly8wGyiNdE3TVWgCEN5YRaTLpfV02c4ECyKk713EXRAtQCmdty0yxv5ak9ey\r\n' +
//                 'XDUVd4a8T3QMgHcAOTXWMFJNUjeeiIdiThDbURJEv+9F+DW+4w5py2iw0PYJ\r\n' +
//                 'Nm6iAHCjoPQTbGLxstl2BYSocZWxG1usoPKhbugGZK0Vr8rdpsfakjJ9cJUg\r\n' +
//                 'YHIH3VT+y+u5mhY681NrB5koRUxDT6ridbytMcoK8xpqYG3FhC8CiVnzpDQ3\r\n' +
//                 'o1KRkWuxUq66oJhu0wungXcqaDzDUEfeUjMuKVI/d9/ViXy8IH/XdlOy0lLY\r\n' +
//                 'Oac0ovRjb7zgeVOp2e7N4eTu0dts3SE+Do1gyqZo2rf1dwsJQI9YUtpjYAtr\r\n' +
//                 'NBkKyRvBAhg9KPh1y2Y1u3ra5OS0yGuNDD8pXdiN3kxMt5OBlnWeFjL6ll7+\r\n' +
//                 'vgiKZooPUZPbFIWi4XBXTv7D5T9THDYmuJpcOffn1AA7j2FM8fkFvtiFyw9J\r\n' +
//                 '2S14penv2R7TeybxR6ktD7HtZd34gmGvmOxhWRNU/vfp4SisUcu9jzQq+cJt\r\n' +
//                 'joWuJiZ8xvWEC2DD32n9bWyIlGhS4hATqz/gEdSha8hxzT+GJi29jYjp8Hnc\r\n' +
//                 '9HwxOArz6Q5h/nDN2Xt5PuCM65J0dathzAm0A7BLRQI+4OjTW575sRKvarzH\r\n' +
//                 '8JZ+UYK2BgP4Kbh9JqhnD/2NKD/csuL6No5guyOH8+zekdBtFE394SV8e9N+\r\n' +
//                 'zYgzVex4SDG8y/YO7W7Tp6afNb+sqyzEw5Bknypn0Hc3cr9wy1P8jLMM2woL\r\n' +
//                 'GRDZ5IutCAV/D/h881dHJs0tV2hpdGVvdXQgVXNlciA8c2FmZXdpdGhtZS50\r\n' +
//                 'ZXN0dXNlckBnbWFpbC5jb20+wsBcBBABCAAQBQJSjg7aCRDX+5P837/CPAAA\r\n' +
//                 '3ZwH/2AVGYB+8RDarP5a5uZPYSxJKeM8zHMbi7LKQWhr5NpkJajZdra1CCGZ\r\n' +
//                 'TXTeQSRBvU4SNGOmDAlhf0qCGeXwMHIzrzovkBedHIc/vypEkItdJeXQAaJx\r\n' +
//                 'uhQOnmyi9priuzBBx4e9x1aBn+aAdNGiJB4l13L2T4fow8WLIVpVwXB6BWya\r\n' +
//                 'lz50JwLzJP6qHxkhvIZElTrQ+Yoo3stS6w/7wNtK/f3MIYkIGVVUrIDgzN0X\r\n' +
//                 'm4z6ypN1dsrM6tPkMZ0JlqjHiz7DXpKrWsfNkoVZ9A98osMH2nIDS58JVEDc\r\n' +
//                 'AXoFSLsbdmqFmIc2Ew828TjlX+FLU9tlx89WhSMTapzUjHU=\r\n' +
//                 '=wxuK\r\n' +
//                 '-----END PGP PRIVATE KEY BLOCK-----';

//             pubkeyArmored = '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n' +
//                 'Version: OpenPGP.js v.1.20131116\r\n' +
//                 'Comment: Whiteout Mail - http://whiteout.io\r\n' +
//                 '\r\n' +
//                 'xsBNBFKODs4BB/9iOF4THsjQMY+WEpT7ShgKxj4bHzRRaQkqczS4nZvP0U3g\r\n' +
//                 'qeqCnbpagyeKXA+bhWFQW4GmXtgAoeD5PXs6AZYrw3tWNxLKu2Oe6Tp9K/XI\r\n' +
//                 'xTMQ2wl4qZKDXHvuPsJ7cmgaWqpPyXtxA4zHHS3WrkI/6VzHAcI/y6x4szSB\r\n' +
//                 'KgSuhI3hjh3s7TybUC1U6AfoQGx/S7e3WwlCOrK8GTClirN/2mCPRC5wuIft\r\n' +
//                 'nkoMfA6jK8d2OPrJ63shy5cgwHOjQg/xuk46dNS7tkvGmbaa+X0PgqSKB+Hf\r\n' +
//                 'YPPNS/ylg911DH9qa8BqYU2QpNh9jUKXSF+HbaOM+plWkCSAL7czV+R3ABEB\r\n' +
//                 'AAHNLVdoaXRlb3V0IFVzZXIgPHNhZmV3aXRobWUudGVzdHVzZXJAZ21haWwu\r\n' +
//                 'Y29tPsLAXAQQAQgAEAUCUo4O2gkQ1/uT/N+/wjwAAN2cB/9gFRmAfvEQ2qz+\r\n' +
//                 'WubmT2EsSSnjPMxzG4uyykFoa+TaZCWo2Xa2tQghmU103kEkQb1OEjRjpgwJ\r\n' +
//                 'YX9Kghnl8DByM686L5AXnRyHP78qRJCLXSXl0AGicboUDp5sovaa4rswQceH\r\n' +
//                 'vcdWgZ/mgHTRoiQeJddy9k+H6MPFiyFaVcFwegVsmpc+dCcC8yT+qh8ZIbyG\r\n' +
//                 'RJU60PmKKN7LUusP+8DbSv39zCGJCBlVVKyA4MzdF5uM+sqTdXbKzOrT5DGd\r\n' +
//                 'CZaox4s+w16Sq1rHzZKFWfQPfKLDB9pyA0ufCVRA3AF6BUi7G3ZqhZiHNhMP\r\n' +
//                 'NvE45V/hS1PbZcfPVoUjE2qc1Ix1\r\n' +
//                 '=7Wpe\r\n' +
//                 '-----END PGP PUBLIC KEY BLOCK-----';

//             pgpbuilder = new PgpBuilder(opts, openpgp);

//             pgpbuilder.setPrivateKey({
//                 privateKeyArmored: privKey,
//                 passphrase: 'passphrase'
//             }, function(err) {
//                 expect(err).to.not.exist;
//                 done();
//             });
//         });

//         describe('send', function() {
//             it('should send a message with attachments and decode the output correctly', function(done) {
//                 this.timeout(10000);

//                 var cb, mail, publicKeysArmored, expectedAttachmentPayload, cleartextMessage;

//                 //
//                 // Setup Fixture
//                 //

//                 cleartextMessage = 'yes! this is very secure!';
//                 publicKeysArmored = [pubkeyArmored];

//                 var size = 10000;
//                 if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
//                     var arr = new Uint8Array(size);
//                     window.crypto.getRandomValues(arr);
//                     expectedAttachmentPayload = arr;
//                 } else {
//                     // node.js
//                     var randomBinStr = require('crypto').randomBytes(size).toString('binary');
//                     expectedAttachmentPayload = s2a(randomBinStr);
//                 }

//                 var body = 'hello, world!';
//                 mail = {
//                     from: [{
//                         address: 'a@a.io'
//                     }],
//                     to: [{
//                         address: 'b@b.io'
//                     }, {
//                         address: 'c@c.io'
//                     }],
//                     subject: 'foobar',
//                     body: body,
//                     attachments: [{
//                         mimeType: 'text/x-markdown',
//                         filename: 'a.txt',
//                         content: expectedAttachmentPayload
//                     }]
//                 };
//                 cb = function(err, mail) {
//                     //
//                     // Verification
//                     //

//                     expect(err).to.not.exist;
//                     expect(mail).to.exist;

//                     var pgpMessageObj = openpgp.message.readArmored(mail.body);
//                     var publicKeyObj = openpgp.key.readArmored(pubkeyArmored).keys[0];

//                     var decrypted = openpgp.decryptAndVerifyMessage(pgpbuilder._privateKey, [publicKeyObj], pgpMessageObj);
//                     expect(decrypted).to.exist;
//                     expect(decrypted.signatures[0].valid).to.be.true;
//                     expect(decrypted.text).to.exist;

//                     var parser = new MailParser();
//                     parser.on('end', function(parsedMail) {
//                         expect(parsedMail).to.exist;
//                         expect(parsedMail.text.replace(/\n/g, '')).to.equal(body);
//                         var attachmentBinStr = parsedMail.attachments[0].content.toString('binary');
//                         var attachmentPayload = s2a(attachmentBinStr);
//                         expect(attachmentPayload.length).to.equal(expectedAttachmentPayload.length);
//                         expect(attachmentPayload).to.deep.equal(expectedAttachmentPayload);

//                         done();
//                     });
//                     parser.end(decrypted.text);
//                 };

//                 //
//                 // Prepare SUT
//                 //

//                 // queue the mail
//                 pgpbuilder.encrypt({
//                     mail: mail,
//                     publicKeysArmored: publicKeysArmored
//                 }, cb);
//             });
//         });
//     });

//     //
//     // Helper Functions
//     //

//     function s2a(str) {
//         var view = new Uint8Array(str.length);
//         for (var i = 0, j = str.length; i < j; i++) {
//             view[i] = str.charCodeAt(i);
//         }
//         return view.buffer;
//     }
// });