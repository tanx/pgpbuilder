if (typeof module === 'object' && typeof define !== 'function') {
    var define = function(factory) {
        'use strict';

        module.exports = factory(require, exports, module);
    };
}

define(function(require) {
    'use strict';

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


        // decrypt the private key (for signing)
        try {
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
     * Creates a signed MIME-tree and encrypts it. Attaches an encrypted = true flag to options.mail if successful.
     * @param {String} options.mail.body Plain text body to be sent with the mail
     * @param {Array} options.mail.attachments (optional) Array of attachment objects with filename {String}, content {Uint8Array}, and mimeType {String}
     * @param {Array} options.publicKeysArmored The public keys with which the message should be encrypted
     * @param {Function} callback(error, mail) Invoked when the mail has been encrypted, or contains information in case of an error
     */
    PgpBuilder.prototype.encrypt = function(options, callback, builder) {
        var self = this,
            mailbuilder;

        if (!this._privateKey) {
            callback(new Error('No private key has been set. Cannot sign mails!'));
            return;
        }

        mailbuilder = builder || new Mailbuilder();

        options.mail.attachments = options.mail.attachments || [];

        // create the signed mime tree
        self._createSignedMimeTree(options.mail, mailbuilder, onSigned);

        function onSigned(err) {
            if (err) {
                callback(err);
                return;
            }

            var plaintext = mailbuilder.node.build(),
                publicKeys = [];

            // parse the ASCII-armored public keys to encrypt the signed mime tree
            try {
                options.publicKeysArmored.forEach(function(key) {
                    publicKeys.push(openpgp.key.readArmored(key).keys[0]);
                });
            } catch (err) {
                callback(err);
                return;
            }

            // encrypt the signed mime tree
            openpgp.signAndEncryptMessage(publicKeys, self._privateKey, plaintext, onEncrypted);
        }

        function onEncrypted(err, ciphertext) {
            if (err) {
                callback(err);
                return;
            }

            // replace the mail body with the ciphertext and empty the attachment 
            // (attachment is now within the ciphertext!)
            options.mail.encrypted = true;
            options.mail.body = ciphertext;
            options.mail.attachments.length = 0;

            callback(null, options.mail);
        }
    };

    /**
     * Decrypts an encrypted mail body and re-encrypts it with a new set of public keys. Attaches an encrypted = true flag to options.mail if successful.
     * @param {String} options.mail.body Plain text body to be sent with the mail
     * @param {Array} options.publicKeysArmored The new set of public keys with which the message should be encrypted
     * @param {Function} callback(error, mail) Invoked when the mail has been re-encrypted, or contains information in case of an error
     */
    PgpBuilder.prototype.reEncrypt = function(options, callback) {
        var self = this,
            publicKeys = [];

        if (!self._privateKey) {
            callback(new Error('No private key has been set. Cannot re-encrypt mails!'));
            return;
        }

        // decrypt the pgp message to retrieve the plain text
        openpgp.decryptMessage(this._privateKey, options.mail.body, onDecrypted);

        function onDecrypted(err, decrypted) {
            if (err) {
                callback(err);
                return;
            }

            // parse the ASCII-armored public keys to encrypt the body
            try {
                options.publicKeysArmored.forEach(function(key) {
                    publicKeys.push(openpgp.key.readArmored(key).keys[0]);
                });
            } catch (err) {
                callback(err);
                return;
            }

            // re-encrypt the plain text
            openpgp.signAndEncryptMessage(publicKeys, self._privateKey, decrypted, onEncrypted);
        }

        function onEncrypted(err, ciphertext) {
            if (err) {
                callback(err);
                return;
            }

            // place the newly encrypted ciphertext in the mail body
            options.mail.body = ciphertext;

            callback(null, options.mail);
        }
    };

    /**
     * Builds the complete encrypted RFC message to be sent via SMTP. It is necessary to call encrypt() before.
     * @param {Object} options.mail.from Array containing one object with the ASCII string representing the sender address, e.g. 'foo@bar.io'
     * @param {String} options.mail.body PGP-Encrypted mail body
     * @param {Array} options.mail.to (optional) Array of ASCII strings representing the recipient (e.g. ['the.dude@lebowski.com', 'donny@kerabatsos.com'])
     * @param {Array} options.mail.cc (optional) Array of ASCII strings representing the recipient, see mail.to
     * @param {Array} options.mail.bcc (optional) Array of ASCII strings representing the recipient, see mail.to
     * @param {String} options.mail.subject String containing with the mail's subject
     * @param {Object} options.cleartextMessage (optional) A clear text message in addition to the encrypted message
     * @param {Function} callback(error, rfcMessage, smtpInfo) Invoked when the mail has been built and the smtp information has been created, or gives information in case an error occurred.
     */
    PgpBuilder.prototype.buildEncrypted = function(options, callback, builder) {
        var self = this,
            mailbuilder;

        // only build the encrypted rfc message for mails that have been encrypted before...
        if (!options.mail.encrypted) {
            callback(new Error('The mail was not encrypted'));
        }

        mailbuilder = builder || new Mailbuilder();

        // configure the envelope
        self._setBuilderEnvelope(options.mail, mailbuilder);

        // create the PGP/MIME tree
        self._createPgpMimeTree(options.cleartextMessage, options.mail.body, mailbuilder);

        callback(null, mailbuilder.build(), mailbuilder.getEnvelope());
    };

    /**
     * Builds the signed cleartext RFC message to be sent via SMTP
     * @param {Object} options.mail.from Array containing one object with the ASCII string representing the sender address, e.g. 'foo@bar.io'
     * @param {Array} options.mail.to (optional) Array of ASCII strings representing the recipient (e.g. ['the.dude@lebowski.com', 'donny@kerabatsos.com'])
     * @param {Array} options.mail.cc (optional) Array of ASCII strings representing the recipient, see mail.to
     * @param {Array} options.mail.bcc (optional) Array of ASCII strings representing the recipient, see mail.to
     * @param {String} options.mail.subject String containing with the mail's subject
     * @param {String} options.mail.body Plain text body to be sent with the mail
     * @param {Array} options.mail.attachments (optional) Array of attachment objects with filename {String}, content {Uint8Array}, and mimeType {String}
     * @param {Function} callback(error, rfcMessage, smtpInfo) Invoked when the mail has been built and the smtp information has been created, or gives information in case an error occurred.
     */
    PgpBuilder.prototype.buildSigned = function(options, callback, builder) {
        var self = this,
            mailbuilder;

        if (!this._privateKey) {
            callback(new Error('No private key has been set. Cannot sign mails!'));
            return;
        }

        mailbuilder = builder || new Mailbuilder();

        // create a signed mime tree
        self._createSignedMimeTree(options.mail, mailbuilder, onSigned);

        function onSigned(err) {
            if (err) {
                callback(err);
                return;
            }

            // configure the envelope data
            self._setBuilderEnvelope(options.mail, mailbuilder);

            callback(null, mailbuilder.build(), mailbuilder.getEnvelope());
        }
    };

    PgpBuilder.prototype._setBuilderEnvelope = function(mail, builder) {
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
    };

    PgpBuilder.prototype._createSignedMimeTree = function(mail, builder, localCallback) {
        var self = this,
            parentNode, contentNode, signatureNode,
            cleartext, signatureHeader;

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

    PgpBuilder.prototype._createPgpMimeTree = function(cleartextMessage, ciphertext, builder) {
        var multipartParentNode, encryptedNode;

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
    };

    return PgpBuilder;
});