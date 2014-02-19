'use strict';

if (typeof module === 'object' && typeof define !== 'function') {
    var define = function(factory) {
        module.exports = factory(require, exports, module);
    };
}

define(function(require) {
    var openpgp = require('openpgp'),
        Mailbuilder = require('mailbuilder'),
        PgpBuilder;

    /**
     * Constructor for the PGP builder
     * @param {String} pgpWorkerPath The path to the openpgp async source initialize a Wek Worker
     */
    PgpBuilder = function(options, pgp) {
        options = options || {};
        this._pgp = pgp || openpgp;

        // set pgp worker path for in browser use
        if (typeof window !== 'undefined' && window.Worker && options.pgpWorkerPath) {
            openpgp.initWorker(options.pgpWorkerPath);
        }
    };

    /**
     * Set the private key used to sign your messages
     * @param {String} options.privateKey ASCII-armored private key to sign the messages
     * @param {String} options.passphrase The passphrase to encrypt options.armoredPrivateKey
     * @param {Function} callback(error) Indicates that the private key has been set, or provides error information
     */
    PgpBuilder.prototype.setPrivateKey = function(options, callback) {
        var privateKey;

        try {
            // decrypt the private key (for signing)
            privateKey = openpgp.key.readArmored(options.privateKeyArmored).keys[0];
            if (!privateKey.decrypt(options.passphrase)) {
                callback(new Error('Wrong passphrase! Could not decrypt the private key!'));
                return;
            }
        } catch (err) {
            callback(err);
            return;
        }

        this._privateKey = privateKey;
        callback();
    };

    /**
     * Queues a mail object for sending.
     * @param {Boolean} options.encrypt (optional) If true, the message will be encrypted with the public keys in options.publicKeysArmored. Otherwise, the message will be signed with the private key and sent in the clear. Default: false
     * @param {Object} options.mail.from Array containing one object with the ASCII string representing the sender address, e.g. 'foo@bar.io'
     * @param {Array} options.mail.to (optional) Array of objects with the ASCII string representing the recipient (e.g. ['the.dude@lebowski.com', 'donny@kerabatsos.com'])
     * @param {Object} options.mail.cc (optional) Array of objects with the ASCII string representing the recipient, see mail.to
     * @param {Object} options.mail.bcc (optional) Array of objects with the ASCII string representing the recipient, see mail.to
     * @param {String} options.mail.subject String containing with the mail's subject
     * @param {String} options.mail.body Plain text body to be sent with the mail
     * @param {Array} options.mail.attachments (optional) Array of attachment objects with filename {String}, content {Uint8Array}, and mimeType {String}
     * @param {Object} options.cleartextMessage (optional) A clear text message in addition to the encrypted message
     * @param {Array} options.publicKeysArmored The public keys with which the message should be encrypted
     * @param {Function} callback(error, envelope, rfcMessage) Indicates that the mail has been sent, or gives information in case an error occurred.
     */
    PgpBuilder.prototype.build = function(options, callback, builder) {
        var self = this,
            mailbuilder;

        if (!this._privateKey) {
            callback(new Error('No private key has been set. Cannot sign mails!'));
            return;
        }

        mailbuilder = builder || new Mailbuilder();

        self._createMimeTree(options.mail, mailbuilder, function(err) {
            if (err) {
                callback(err);
                return;
            }

            if (options.encrypt) {
                // if necessary, encrypt the message!
                self._encrypt(options.cleartextMessage, options.publicKeysArmored, mailbuilder, function(err) {
                    if (err) {
                        callback(err);
                        return;
                    }

                    callback(null, mailbuilder.getEnvelope, mailbuilder.build());
                });
                return;
            }

            callback(null, mailbuilder.getEnvelope(), mailbuilder.build());
        });
    };

    PgpBuilder.prototype._createMimeTree = function(mail, builder, localCallback) {
        var self = this,
            parentNode, contentNode, signatureNode,
            cleartext, signatureHeader;

        // 
        // create the envelope data
        // 

        builder.setSubject(mail.subject);

        // add everyone's addresses
        builder.setFrom(mail.from[0].address || mail.from[0]);

        if (mail.to) {
            mail.to.forEach(function(recipient) {
                builder.addTo(recipient.address || recipient);
            });
        }

        if (mail.cc) {
            mail.cc.forEach(function(recipient) {
                builder.addCc(recipient.address || recipient);
            });
        }

        if (mail.bcc) {
            mail.bcc.forEach(function(recipient) {
                builder.addBcc(recipient.address || recipient);
            });
        }


        // 
        // create the mime tree
        // 

        parentNode = builder.createNode([{
            key: 'Content-Type',
            value: 'multipart/signed',
            parameters: {
                micalg: 'pgp-sha256',
                protocol: 'application/pgp-signature'
            }
        }]);

        // this a plain text mail? then only one text/plain node is needed
        if (!mail.attachments || mail.attachments.length === 0) {
            contentNode = parentNode.createNode([{
                key: 'Content-Type',
                value: 'text/plain',
                parameters: {
                    charset: 'utf-8'
                }
            }, {
                key: 'Content-Transfer-Encoding',
                value: 'quoted-printable'
            }]);
            contentNode.content = mail.body;
        } else {
            // we have attachments, so let's create a multipart/mixed mail
            contentNode = parentNode.createNode([{
                key: 'Content-Type',
                value: 'multipart/mixed',
            }]);

            // create the text/plain node
            contentNode.createNode([{
                key: 'Content-Type',
                value: 'text/plain',
                parameters: {
                    charset: 'utf-8'
                }
            }, {
                key: 'Content-Transfer-Encoding',
                value: 'quoted-printable'
            }]).content = mail.body;

            // add the attachments
            mail.attachments.forEach(function(attmt) {
                contentNode.createNode([{
                    key: 'Content-Type',
                    value: attmt.mimeType || 'application/octet-stream'
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: 'base64'
                }, {
                    key: 'Content-Disposition',
                    value: 'attachment',
                    parameters: {
                        filename: attmt.filename
                    }
                }]).content = attmt.content;
            });
        }

        //
        // Sign the whole thing
        //

        signatureNode = parentNode.createNode([{
            key: 'Content-Type',
            value: 'application/pgp-signature'
        }, {
            key: 'Content-Transfer-Encoding',
            value: '7bit'
        }]);

        cleartext = contentNode.build().trim() + '\r\n';
        openpgp.config.prefer_hash_algorithm = openpgp.enums.hash.sha256;
        openpgp.signClearMessage([self._privateKey], cleartext, onSigned);

        function onSigned(err, signedCleartext) {
            if (err) {
                localCallback(err);
                return;
            }

            signatureHeader = "-----BEGIN PGP SIGNATURE-----";
            signatureNode.content = signatureHeader + signedCleartext.split(signatureHeader).pop();

            localCallback();
        }
    };

    PgpBuilder.prototype._encrypt = function(cleartextMessage, publicKeysArmored, builder, localCallback) {
        var self = this,
            publicKeys = [],
            plaintext,
            multipartParentNode, encryptedNode;

        // prepare the plain text mime nodes
        plaintext = builder.node.build();

        try {
            // parse the ASCII-armored public keys
            publicKeysArmored.forEach(function(key) {
                publicKeys.push(openpgp.key.readArmored(key).keys[0]);
            });
        } catch (err) {
            localCallback(err);
            return;
        }

        // encrypt the plain text
        openpgp.signAndEncryptMessage(publicKeys, self._privateKey, plaintext, onEncrypted);

        function onEncrypted(err, ciphertext) {
            if (err) {
                localCallback(err);
                return;
            }

            // delete the plain text from the builder
            delete builder.node;

            // do we need to frame the encrypted message with a clear text?
            if (cleartextMessage) {
                // create a multipart/mixed message
                multipartParentNode = builder.createNode([{
                    key: 'Content-Type',
                    value: 'multipart/mixed',
                }]);

                multipartParentNode.createNode([{
                    key: 'Content-Type',
                    value: 'text/plain',
                    parameters: {
                        charset: 'utf-8'
                    }
                }, {
                    key: 'Content-Transfer-Encoding',
                    value: 'quoted-printable'
                }]).content = cleartextMessage;
            }

            // create a pgp/mime message
            // either pin the encrypted mime-subtree under the multipart/mixed node, OR 
            // create a top-level multipart/encrypted node
            encryptedNode = (multipartParentNode || builder).createNode([{
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
            }]);
            encryptedNode.content = 'This is an OpenPGP/MIME encrypted message.';

            // set the version info
            encryptedNode.createNode([{
                key: 'Content-Type',
                value: 'application/pgp-encrypted'
            }, {
                key: 'Content-Transfer-Encoding',
                value: '7bit'
            }, {
                key: 'Content-Description',
                value: 'PGP/MIME Versions Identification'
            }]).content = 'Version: 1';

            // set the ciphertext
            encryptedNode.createNode([{
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
            }]).content = ciphertext;

            localCallback();
        }
    };

    return PgpBuilder;
});