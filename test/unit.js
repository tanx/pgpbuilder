'use strict';

if (typeof module === 'object' && typeof define !== 'function') {
    var define = function(factory) {
        module.exports = factory(require, exports, module);
    };
}

define(function(require) {
    var sinon = require('sinon'),
        chai = require('chai'),
        expect = chai.expect,
        PgpBuiler = require('../src/pgpbuilder'),
        Mailbuilder = require('mailbuilder'),
        openpgp = require('openpgp');

    chai.Assertion.includeStack = true;

    describe('unit tests', function() {
        var pgpbuilder, builderMock,
            rootNodeMock, contentNodeMock, signatureNodeMock,
            encryptedRootMock, multipartRootMock;

        beforeEach(function() {
            var opts;

            rootNodeMock = sinon.createStubInstance(Mailbuilder.Node);
            contentNodeMock = sinon.createStubInstance(Mailbuilder.Node);
            signatureNodeMock = sinon.createStubInstance(Mailbuilder.Node);

            multipartRootMock = sinon.createStubInstance(Mailbuilder.Node);
            encryptedRootMock = sinon.createStubInstance(Mailbuilder.Node);
            builderMock = sinon.createStubInstance(Mailbuilder);
            builderMock.node = rootNodeMock;

            pgpbuilder = new PgpBuiler(opts, openpgp);
            pgpbuilder._privateKey = 'asdasdasdasd';
        });

        describe('set private key', function() {
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

                pgpbuilder.setPrivateKey(opts, function(err) {
                    expect(err).to.not.exist;
                    expect(readArmoredStub.calledWith(opts.privateKeyArmored)).to.be.true;
                    expect(pgpbuilder._privateKey).to.exist;

                    done();
                });
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

                pgpbuilder.setPrivateKey(opts, function(err) {
                    expect(err).to.exist;
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

                pgpbuilder.setPrivateKey(opts, function(err) {
                    expect(err).to.exist;
                    expect(readArmoredStub.calledWith(opts.privateKeyArmored)).to.be.true;
                    expect(pgpbuilder._privateKey).to.not.exist;

                    done();
                });
            });
        });


        describe('buildSigned', function() {
            it('should build signed plaintext rfc', function(done) {
                var mail, mockBody, mockCompiledMail, mockPlaintext, signClearStub, mockSignature;

                mockBody = 'trollolololo';
                mockCompiledMail = 'wow much mail';
                mockSignature = '-----BEGIN PGP SIGNATURE-----UMBAPALLUMBA-----END PGP SIGNATURE-----';
                mockPlaintext = 'dsgsleahfbaldsjgnse';
                
                mail = {
                    from: [{ address: 'a@a.io' }],
                    to: [{ address: 'b@b.io'}, { address: 'c@c.io' }],
                    cc: [{ address: 'd@d.io' }],
                    bcc: [{ address: 'e@e.io' }],
                    subject: 'foobar',
                    encrypted: true,
                    body: mockBody,
                    attachments: [{
                        mimeType: 'text/plain',
                        filename: 'a.txt',
                        content: utf16ToUInt8Array('attachment1')
                    }]
                };

                signClearStub = sinon.stub(openpgp, 'signClearMessage');
                signClearStub.withArgs([pgpbuilder._privateKey], mockPlaintext.trim() + '\r\n').yields(null, mockSignature);
                contentNodeMock.build.returns(mockPlaintext);
                builderMock.getEnvelope.returns({});
                builderMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'multipart/signed',
                    parameters: {
                        micalg: 'pgp-sha256',
                        protocol: 'application/pgp-signature'
                    }
                }]).returns(rootNodeMock);

                contentNodeMock.build.returns(mockPlaintext);
                builderMock.getEnvelope.returns({});
                builderMock.build.returns(mockCompiledMail);

                rootNodeMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'multipart/mixed',
                }]).returns(contentNodeMock);

                rootNodeMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'application/pgp-signature'
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: '7bit'
                }]).returns(signatureNodeMock);

                contentNodeMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'text/plain',
                    parameters: {
                        charset: 'utf-8'
                    }
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: 'quoted-printable'
                }]).returns({});

                contentNodeMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: mail.attachments[0].mimeType
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: 'base64'
                }, {
                    key: 'Content-Disposition',
                    value: 'attachment',
                    parameters: {
                        filename: mail.attachments[0].filename
                    }
                }]).returns({});

                pgpbuilder.buildSigned({
                    mail: mail,
                }, function(error, build, envelope) {
                    expect(error).to.not.exist;
                    expect(build).to.exist;
                    expect(envelope).to.exist;

                    expect(builderMock.createNode.calledOnce).to.be.true;
                    expect(rootNodeMock.createNode.calledTwice).to.be.true;
                    expect(contentNodeMock.createNode.calledTwice).to.be.true;

                    expect(builderMock.setSubject.calledOnce).to.be.true;
                    expect(builderMock.setFrom.calledOnce).to.be.true;
                    expect(builderMock.addTo.calledTwice).to.be.true;
                    expect(builderMock.addCc.calledOnce).to.be.true;
                    expect(builderMock.addBcc.calledOnce).to.be.true;
                    expect(builderMock.setSubject.calledWith(mail.subject)).to.be.true;
                    expect(builderMock.setFrom.calledWith(mail.from[0].address)).to.be.true;
                    expect(builderMock.addTo.calledWith(mail.to[0].address)).to.be.true;
                    expect(builderMock.addTo.calledWith(mail.to[1].address)).to.be.true;
                    expect(builderMock.addCc.calledWith(mail.cc[0].address)).to.be.true;
                    expect(builderMock.addBcc.calledWith(mail.bcc[0].address)).to.be.true;

                    openpgp.signClearMessage.restore();

                    done();
                }, builderMock);
            });
        });

        describe('buildEncrypted', function() {
            it('should build encrypted rfc', function() {
                var mail, mockBody, mockCleartext, mockCompiledMail;

                mockBody = 'trollolololo';
                mockCleartext = 'dfliablgiabdfliubsdl';
                mockCompiledMail = 'wow much mail';
                mail = {
                    from: [{ address: 'a@a.io' }],
                    to: [{ address: 'b@b.io'}, { address: 'c@c.io' }],
                    cc: [{ address: 'd@d.io' }],
                    bcc: [{ address: 'e@e.io' }],
                    subject: 'foobar',
                    encrypted: true,
                    body: mockBody
                };

                builderMock.getEnvelope.returns({});
                builderMock.build.returns(mockCompiledMail);

                builderMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'multipart/mixed',
                }]).returns(multipartRootMock);

                multipartRootMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'text/plain',
                    parameters: {
                        charset: 'utf-8'
                    }
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: 'quoted-printable'
                }]).returns({});

                multipartRootMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'multipart/encrypted',
                    parameters: {
                        protocol: 'application/pgp-encrypted'
                    }
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: '7bit'
                }, {
                    key: 'Content-Description',
                    value: 'OpenPGP encrypted message'
                }]).returns(encryptedRootMock);

                encryptedRootMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'application/pgp-encrypted'
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: '7bit'
                }, {
                    key: 'Content-Description',
                    value: 'PGP/MIME Versions Identification'
                }]).returns({});

                encryptedRootMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'application/octet-stream'
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: '7bit'
                }, {
                    key: 'Content-Description',
                    value: 'OpenPGP encrypted message'
                }, {
                    key: 'Content-Disposition',
                    value: 'inline',
                    parameters: {
                        filename: 'encrypted.asc'
                    }
                }]).returns({});

                pgpbuilder.buildEncrypted({
                    mail: mail,
                    cleartextMessage: mockCleartext
                }, function(error, build, envelope) {
                    expect(error).to.not.exist;
                    expect(build).to.exist;
                    expect(envelope).to.exist;

                    expect(builderMock.createNode.calledOnce).to.be.true;
                    expect(multipartRootMock.createNode.calledTwice).to.be.true;
                    expect(encryptedRootMock.createNode.calledTwice).to.be.true;

                    expect(builderMock.setSubject.calledOnce).to.be.true;
                    expect(builderMock.setFrom.calledOnce).to.be.true;
                    expect(builderMock.addTo.calledTwice).to.be.true;
                    expect(builderMock.addCc.calledOnce).to.be.true;
                    expect(builderMock.addBcc.calledOnce).to.be.true;
                    expect(builderMock.setSubject.calledWith(mail.subject)).to.be.true;
                    expect(builderMock.setFrom.calledWith(mail.from[0].address)).to.be.true;
                    expect(builderMock.addTo.calledWith(mail.to[0].address)).to.be.true;
                    expect(builderMock.addTo.calledWith(mail.to[1].address)).to.be.true;
                    expect(builderMock.addCc.calledWith(mail.cc[0].address)).to.be.true;
                    expect(builderMock.addBcc.calledWith(mail.bcc[0].address)).to.be.true;
                }, builderMock);
            });
        });

        describe('reencrypt', function() {
            it('should reencrypt', function(done) {
                var readArmoredStub, signAndEncryptStub, decryptStub,
                    encryptedMail, mockCiphertext, mockPlaintext,
                    publicKeysArmored;

                mockCiphertext = 'MORE PGP THAN YOU CAN HANDLE!';
                mockPlaintext = 'BLABLABLABLAYADDAYADDA\r\n\r\n';

                encryptedMail = {
                    body: mockCiphertext
                };

                publicKeysArmored = ['publicA', 'publicB', 'publicC', 'publicD', 'publicE'];
                decryptStub = sinon.stub(openpgp, 'decryptMessage');
                decryptStub.withArgs(pgpbuilder._privateKey, mockCiphertext).yieldsAsync(null, mockPlaintext);
                signAndEncryptStub = sinon.stub(openpgp, 'signAndEncryptMessage');
                signAndEncryptStub.withArgs(sinon.match.any, pgpbuilder._privateKey, mockPlaintext).yieldsAsync(null, mockCiphertext);
                readArmoredStub = sinon.stub(openpgp.key, 'readArmored');
                readArmoredStub.returns({
                    keys: [{}]
                });

                pgpbuilder.reEncrypt({
                    publicKeysArmored: publicKeysArmored,
                    mail: encryptedMail
                }, function(err, reencryptedMail) {
                    expect(err).to.not.exist;
                    expect(reencryptedMail).to.exist;
                    expect(reencryptedMail).to.equal(encryptedMail);

                    openpgp.key.readArmored.restore();
                    openpgp.signAndEncryptMessage.restore();
                    openpgp.decryptMessage.restore();

                    done();
                });
            });
        });

        describe('encrypt', function() {
            it('should encrypt the mail body', function(done) {
                var mail, publicKeysArmored, mockCiphertext, mockPlaintext, mockSignature,
                    readArmoredStub, signAndEncryptStub, signClearStub,
                    cb;

                publicKeysArmored = ['publicA', 'publicB', 'publicC', 'publicD', 'publicE'];
                mail = {
                    body: 'hello, world!',
                    attachments: [{
                        mimeType: 'text/plain',
                        filename: 'a.txt',
                        content: utf16ToUInt8Array('attachment1')
                    }]
                };

                mockCiphertext = 'MORE PGP THAN YOU CAN HANDLE!';
                mockPlaintext = 'BLABLABLABLAYADDAYADDA\r\n\r\n';
                mockSignature = '-----BEGIN PGP SIGNATURE-----UMBAPALLUMBA-----END PGP SIGNATURE-----';
                signClearStub = sinon.stub(openpgp, 'signClearMessage');
                signClearStub.withArgs([pgpbuilder._privateKey], mockPlaintext.trim() + '\r\n').yields(null, mockSignature);
                signAndEncryptStub = sinon.stub(openpgp, 'signAndEncryptMessage');
                signAndEncryptStub.yields(null, mockCiphertext);
                readArmoredStub = sinon.stub(openpgp.key, 'readArmored');
                readArmoredStub.returns({
                    keys: [{}]
                });

                contentNodeMock.build.returns(mockPlaintext);
                builderMock.getEnvelope.returns({});
                builderMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'multipart/signed',
                    parameters: {
                        micalg: 'pgp-sha256',
                        protocol: 'application/pgp-signature'
                    }
                }]).returns(rootNodeMock);

                rootNodeMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'multipart/mixed',
                }]).returns(contentNodeMock);

                rootNodeMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'application/pgp-signature'
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: '7bit'
                }]).returns(signatureNodeMock);

                contentNodeMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: 'text/plain',
                    parameters: {
                        charset: 'utf-8'
                    }
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: 'quoted-printable'
                }]).returns({});

                contentNodeMock.createNode.withArgs([{
                    key: 'Content-Type',
                    value: mail.attachments[0].mimeType
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: 'base64'
                }, {
                    key: 'Content-Disposition',
                    value: 'attachment',
                    parameters: {
                        filename: mail.attachments[0].filename
                    }
                }]).returns({});

                cb = function(err, message) {
                    //
                    // Verification
                    //

                    expect(err).to.not.exist;
                    expect(message).to.exist;
                    expect(message.attachments).to.be.empty;
                    expect(message.encrypted).to.be.true;

                    // check that the mailbuilder has built a clear text and a pgp mail and compiled the pgp mail
                    expect(builderMock.createNode.calledOnce).to.be.true;
                    expect(rootNodeMock.createNode.calledTwice).to.be.true;
                    expect(contentNodeMock.createNode.calledTwice).to.be.true;

                    // check that the pgp lib was called
                    expect(signClearStub.calledOnce).to.be.true;
                    expect(readArmoredStub.callCount).to.equal(publicKeysArmored.length);
                    publicKeysArmored.forEach(function(armored) {
                        expect(readArmoredStub.calledWith(armored)).to.be.true;
                    });
                    expect(signAndEncryptStub.calledOnce).to.be.true;

                    // restore stubs
                    openpgp.key.readArmored.restore();
                    openpgp.signAndEncryptMessage.restore();
                    openpgp.signClearMessage.restore();

                    done();
                };

                pgpbuilder.encrypt({
                    mail: mail,
                    publicKeysArmored: publicKeysArmored
                }, cb, builderMock);
            });
        });
    });

    //
    // Helper Functions
    //

    function utf16ToUInt8Array(str) {
        var bufView = new Uint16Array(new ArrayBuffer(str.length * 2));
        for (var i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return bufView;
    }
});