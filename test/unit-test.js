(function(factory) {
    'use strict';

    if (typeof define === 'function' && define.amd) {
        ES6Promise.polyfill(); // load ES6 Promises polyfill
        define(['chai', 'sinon', 'emailjs-mime-builder', '../src/pgpbuilder', 'openpgp'], factory);
    } else if (typeof exports === 'object') {
        require('es6-promise').polyfill(); // load ES6 Promises polyfill
        module.exports = factory(require('chai'), require('sinon'), require('emailjs-mime-builder'), require('../src/pgpbuilder'), require('openpgp'));
    }
})(function(chai, sinon, Mailbuild, PgpBuilder, openpgp) {
    'use strict';

    var expect = chai.expect;

    describe('unit tests', function() {
        chai.Assertion.includeStack = true;
        var pgpbuilder;

        beforeEach(function() {
            pgpbuilder = new PgpBuilder(undefined, openpgp);
            pgpbuilder._privateKey = 'asdasdasdasd';
        });

        describe('#setPrivateKey', function() {
            var readArmoredStub;

            beforeEach(function() {
                delete pgpbuilder._privateKey;
                readArmoredStub = sinon.stub(openpgp.key, 'readArmored');
            });

            afterEach(function() {
                openpgp.key.readArmored.restore();
            });

            it('should set the private key', function(done) {
                var opts = {
                    privateKeyArmored: 'PRIVATE KEY',
                    passphrase: 'PASSPHRASE'
                };

                readArmoredStub.returns({
                    keys: [{
                        decrypt: function() {
                            return true;
                        }
                    }]
                });

                pgpbuilder.setPrivateKey(opts).then(function() {
                    expect(readArmoredStub.calledWith(opts.privateKeyArmored)).to.be.true;
                    expect(pgpbuilder._privateKey).to.exist;
                }).then(done);
            });

            it('should not set the private key due to wrong password', function(done) {
                var opts = {
                    privateKeyArmored: 'PRIVATE KEY',
                    passphrase: 'PASSPHRASE'
                };

                readArmoredStub.returns({
                    keys: [{
                        decrypt: function() {
                            return false;
                        }
                    }]
                });

                pgpbuilder.setPrivateKey(opts).catch(function() {
                    expect(readArmoredStub.calledWith(opts.privateKeyArmored)).to.be.true;
                    expect(pgpbuilder._privateKey).to.not.exist;

                    done();
                });
            });

            it('should not set the private key and throw an exception', function(done) {
                var opts = {
                    privateKeyArmored: 'PRIVATE KEY',
                    passphrase: 'PASSPHRASE'
                };

                readArmoredStub.throws('FOOBAR!');

                pgpbuilder.setPrivateKey(opts).catch(function(err) {
                    expect(err).to.exist;
                    expect(readArmoredStub.calledWith(opts.privateKeyArmored)).to.be.true;
                    expect(pgpbuilder._privateKey).to.not.exist;

                    done();
                });
            });
        });

        describe('#buildSigned', function() {
            it('should build signed plaintext rfc', function(done) {
                var mail, body, attmt, filename, compiledMail, rfc, signClearStub, sign, envelope;

                var rootNode = sinon.createStubInstance(Mailbuild);
                var contentNode = sinon.createStubInstance(Mailbuild);
                var textNode = sinon.createStubInstance(Mailbuild);
                var attmtNode = sinon.createStubInstance(Mailbuild);
                var signatureNode = sinon.createStubInstance(Mailbuild);

                body = 'trollolololo';
                filename = 'a.txt';
                attmt = s2a('attachment');
                compiledMail = 'wow much mail';
                sign = '-----BEGIN PGP SIGNATURE-----UMBAPALLUMBA-----END PGP SIGNATURE-----';
                rfc = 'dsgsleahfbaldsjgnse';
                envelope = {};

                mail = {
                    from: [{
                        address: 'a@a.io'
                    }],
                    to: [{
                        address: 'b@b.io'
                    }, {
                        address: 'c@c.io'
                    }],
                    cc: [{
                        address: 'd@d.io'
                    }],
                    bcc: [{
                        address: 'e@e.io'
                    }],
                    subject: 'foobar',
                    body: body,
                    attachments: [{
                        mimeType: 'foo/bar',
                        filename: filename,
                        content: attmt
                    }]
                };


                rootNode.createChild.withArgs('multipart/mixed').returns(contentNode);
                contentNode.createChild.withArgs('text/plain').returns(textNode);
                contentNode.createChild.withArgs('application/octet-stream').returns(attmtNode);
                rootNode.createChild.withArgs('application/pgp-signature').returns(signatureNode);

                contentNode.build.returns(rfc);
                signClearStub = sinon.stub(openpgp.default, 'sign');
                signClearStub.withArgs({ privateKeys:[pgpbuilder._privateKey], data:rfc }).returns(new Promise(function(resolve) {
                    resolve({ data:sign });
                }));

                rootNode.build.returns(compiledMail);
                rootNode.getEnvelope.returns(envelope);

                pgpbuilder.buildSigned({
                    mail: mail,
                    rootNode: rootNode // test only
                }).then(function(build) {
                    expect(build.rfcMessage).to.equal(compiledMail);
                    expect(build.smtpInfo).to.equal(envelope);

                    expect(rootNode.setHeader.calledWith('content-type', 'multipart/signed; micalg=pgp-sha256; protocol=application/pgp-signature')).to.be.true;
                    expect(textNode.setHeader.calledWith('content-transfer-encoding', 'quoted-printable')).to.be.true;
                    expect(textNode.setContent.calledWith(body)).to.be.true;
                    expect(attmtNode.setContent.calledWith(attmt)).to.be.true;
                    expect(attmtNode.setHeader.calledWith('content-transfer-encoding', 'base64')).to.be.true;
                    expect(signatureNode.setHeader.calledWith('content-transfer-encoding', '7bit')).to.be.true;

                    expect(mail.bodyParts[0].type).to.equal('signed');
                    expect(mail.bodyParts[0].content[0].type).to.equal('text');
                    expect(mail.bodyParts[0].content[0].content).to.equal(body);
                    expect(mail.bodyParts[0].content[1].type).to.equal('attachment');
                    expect(mail.bodyParts[0].content[1].content).to.equal(attmt);

                    expect(rootNode.setHeader.calledWith({
                        subject: mail.subject,
                        from: mail.from,
                        to: mail.to,
                        cc: mail.cc,
                        bcc: mail.bcc
                    })).to.be.true;

                    signClearStub.restore();
                }).then(done);
            });
        });

        describe('#encrypt', function() {
            it('should encrypt mail', function(done) {
                var mail, body, attmt, filename, compiledMail, rfc, sign, keys, ct;

                var rootNode = sinon.createStubInstance(Mailbuild),
                    contentNode = sinon.createStubInstance(Mailbuild),
                    textNode = sinon.createStubInstance(Mailbuild),
                    attmtNode = sinon.createStubInstance(Mailbuild),
                    signatureNode = sinon.createStubInstance(Mailbuild),
                    signClearStub = sinon.stub(openpgp.default, 'sign'),
                    signAndEncryptStub = sinon.stub(openpgp.default, 'encrypt'),
                    readArmoredStub = sinon.stub(openpgp.key, 'readArmored');

                body = 'trollolololo';
                filename = 'a.txt';
                attmt = s2a('attachment');
                compiledMail = 'wow much mail';
                sign = '-----BEGIN PGP SIGNATURE-----UMBAPALLUMBA-----END PGP SIGNATURE-----';
                rfc = 'dsgsleahfbaldsjgnse';
                keys = ['publicA'];
                ct = 'serious pgp.';

                mail = {
                    from: [{
                        address: 'a@a.io'
                    }],
                    to: [{
                        address: 'b@b.io'
                    }, {
                        address: 'c@c.io'
                    }],
                    cc: [{
                        address: 'd@d.io'
                    }],
                    bcc: [{
                        address: 'e@e.io'
                    }],
                    subject: 'foobar',
                    body: body,
                    attachments: [{
                        mimeType: 'foo/bar',
                        filename: filename,
                        content: attmt
                    }]
                };

                rootNode.createChild.withArgs('multipart/mixed').returns(contentNode);
                contentNode.createChild.withArgs('text/plain').returns(textNode);
                contentNode.createChild.withArgs('application/octet-stream').returns(attmtNode);
                rootNode.createChild.withArgs('application/pgp-signature').returns(signatureNode);

                contentNode.build.returns(rfc);
                signClearStub.withArgs({ privateKeys:[pgpbuilder._privateKey], data:rfc }).returns(new Promise(function(resolve) {
                    resolve({ data:sign });
                }));

                rootNode.build.returns(compiledMail);

                readArmoredStub.returns({
                    keys: [{}]
                });
                signAndEncryptStub.withArgs({publicKeys:[{}], privateKeys:pgpbuilder._privateKey, data:compiledMail }).returns(new Promise(function(resolve) {
                    resolve({ data:ct });
                }));


                pgpbuilder.encrypt({
                    mail: mail,
                    publicKeysArmored: keys,
                    rootNode: rootNode // test only
                }).then(function(mail) {
                    expect(mail).to.exist;
                    expect(mail.body).to.equal(ct);
                    expect(mail.attachments).to.be.empty;
                    expect(mail.encrypted).to.be.true;
                    expect(mail.bodyParts.length).to.equal(1);
                    expect(mail.bodyParts[0].type).to.equal('encrypted');
                    expect(mail.bodyParts[0].content).to.equal(ct);

                    expect(rootNode.setHeader.calledWith('content-type', 'multipart/signed; micalg=pgp-sha256; protocol=application/pgp-signature')).to.be.true;
                    expect(textNode.setHeader.calledWith('content-transfer-encoding', 'quoted-printable')).to.be.true;
                    expect(textNode.setContent.calledWith(body)).to.be.true;
                    expect(attmtNode.setContent.calledWith(attmt)).to.be.true;
                    expect(attmtNode.setHeader.calledWith('content-transfer-encoding', 'base64')).to.be.true;
                    expect(signatureNode.setHeader.calledWith('content-transfer-encoding', '7bit')).to.be.true;

                    expect(signClearStub.calledOnce).to.be.true;
                    expect(readArmoredStub.calledOnce).to.be.true;
                    expect(signAndEncryptStub.calledOnce).to.be.true;

                    openpgp.key.readArmored.restore();
                    signAndEncryptStub.restore();
                    signClearStub.restore();
                }).then(done);
            });
        });

        describe('#buildEncrypted', function() {
            it('should build an encrypted pgp/mime mail w/o cleartext', function(done) {
                var mail, ct, compiledMail, rfc, envelope;

                var rootNode = sinon.createStubInstance(Mailbuild),
                    versionNode = sinon.createStubInstance(Mailbuild),
                    ctNode = sinon.createStubInstance(Mailbuild);

                ct = 'i am the body.';
                compiledMail = 'i am the compiled mail';
                rfc = 'i am rfc';
                envelope = {};

                mail = {
                    from: [{
                        address: 'a@a.io'
                    }],
                    to: [{
                        address: 'b@b.io'
                    }, {
                        address: 'c@c.io'
                    }],
                    cc: [{
                        address: 'd@d.io'
                    }],
                    bcc: [{
                        address: 'e@e.io'
                    }],
                    subject: 'foobar',
                    headers: {
                        'in-reply-to': 'zzz'
                    },
                    bodyParts: [{
                        type: 'encrypted',
                        content: ct
                    }],
                    encrypted: true
                };

                rootNode.createChild.withArgs('application/pgp-encrypted').returns(versionNode);
                rootNode.createChild.withArgs('application/octet-stream').returns(ctNode);

                rootNode.build.returns(compiledMail);
                rootNode.getEnvelope.returns(envelope);

                pgpbuilder.buildEncrypted({
                    mail: mail,
                    rootNode: rootNode // test only
                }).then(function(build) {
                    expect(build.rfcMessage).to.equal(compiledMail);
                    // expect(build.smtpInfo).to.equal(envelope);

                    expect(rootNode.setHeader.calledWith('content-type', 'multipart/encrypted; protocol=application/pgp-encrypted')).to.be.true;
                    expect(rootNode.setHeader.calledWith('content-transfer-encoding', '7bit')).to.be.true;
                    expect(rootNode.setContent.calledWith('This is an OpenPGP/MIME encrypted message.')).to.be.true;
                    expect(versionNode.setHeader.calledWith('content-description', 'PGP/MIME Versions Identification')).to.be.true;
                    expect(versionNode.setContent.calledWith('Version: 1')).to.be.true;
                    expect(versionNode.setHeader.calledWith('content-transfer-encoding', '7bit')).to.be.true;
                    expect(ctNode.setHeader.calledWith('content-description', 'OpenPGP encrypted message')).to.be.true;
                    expect(ctNode.setHeader.calledWith('content-disposition', 'inline')).to.be.true;
                    expect(ctNode.setHeader.calledWith('content-transfer-encoding', '7bit')).to.be.true;
                    expect(ctNode.setContent.calledWith(ct)).to.be.true;

                    expect(rootNode.setHeader.calledWith({
                        subject: mail.subject,
                        from: mail.from,
                        to: mail.to,
                        cc: mail.cc,
                        bcc: mail.bcc
                    })).to.be.true;

                    expect(rootNode.setHeader.calledWith({
                        'in-reply-to': mail.headers['in-reply-to']
                    })).to.be.true;
                }).then(done);
            });
        });
    });

    //
    // Helper Functions
    //
    //
    function s2a(str) {
        var view = new Uint8Array(str.length);
        for (var i = 0, j = str.length; i < j; i++) {
            view[i] = str.charCodeAt(i);
        }
        return view;
    }
});