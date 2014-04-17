'use strict';
if (typeof exports === 'object' && typeof define !== 'function') {
    var define = function(factory) {
        module.exports = factory(require, exports, module);
    };
}

define(function(require) {
    var openpgp = require('openpgp'),
        Mailbuild = require('mailbuild'),
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
    PgpBuilder.prototype.encrypt = function(options, callback) {
        var self = this;

        if (!this._privateKey) {
            callback(new Error('No private key has been set. Cannot sign mails!'));
            return;
        }

        options.mail.attachments = options.mail.attachments || [];

        var rootNode = options.rootNode || new Mailbuild();

        // create the signed mime tree
        self._createSignedMimeTree(options.mail, rootNode, onBuild);

        function onBuild(err) {
            if (err) {
                callback(err);
                return;
            }

            var plaintext = rootNode.build(),
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
    PgpBuilder.prototype.buildEncrypted = function(options, callback) {
        // only build the encrypted rfc message for mails that have been encrypted before...
        if (!options.mail.encrypted) {
            callback(new Error('The mail was not encrypted'));
        }

        var rootNode = options.rootNode || new Mailbuild();

        // create the PGP/MIME tree
        this._createEncryptedMimeTree(options.cleartextMessage, options.mail.body, rootNode);

        // configure the envelope
        this._setEnvelope(options.mail, rootNode);

        callback(null, rootNode.build(), rootNode.getEnvelope());
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
    PgpBuilder.prototype.buildSigned = function(options, callback) {
        var self = this;

        if (!this._privateKey) {
            callback(new Error('No private key has been set. Cannot sign mails!'));
            return;
        }

        var rootNode = options.rootNode || new Mailbuild();

        // create a signed mime tree
        self._createSignedMimeTree(options.mail, rootNode, onSigned);

        function onSigned(err) {
            if (err) {
                callback(err);
                return;
            }

            // configure the envelope data
            self._setEnvelope(options.mail, rootNode);

            callback(null, rootNode.build(), rootNode.getEnvelope());
        }
    };

    // 
    // create the envelope data
    // 
    PgpBuilder.prototype._setEnvelope = function(mail, rootNode) {
        rootNode.setHeader({
            subject: mail.subject,
            from: mail.from,
            to: mail.to,
            cc: mail.cc,
            bcc: mail.bcc
        });
    };

    PgpBuilder.prototype._createSignedMimeTree = function(mail, rootNode, callback) {
        var contentNode, textNode, attmtNode, signatureNode, cleartext;

        // 
        // create the mime tree
        // 

        rootNode.setHeader('content-type', 'multipart/signed; micalg=pgp-sha256; protocol=application/pgp-signature');

        // this a plain text mail? then only one text/plain node is needed
        if (!mail.attachments || mail.attachments.length === 0) {
            contentNode = rootNode.createChild('text/plain');
            contentNode.setContent(mail.body);
        } else {
            // we have attachments, so let's create a multipart/mixed mail
            contentNode = rootNode.createChild('multipart/mixed');

            // create the text/plain node
            textNode = contentNode.createChild('text/plain');
            textNode.setContent(mail.body);

            // add the attachments
            mail.attachments.forEach(function(attmtObj) {
                attmtNode = contentNode.createChild('application/octet-stream');
                attmtNode.filename = attmtObj.filename;
                attmtNode.setContent(attmtObj.content.buffer);
            });
        }

        //
        // Sign the whole thing
        //

        cleartext = contentNode.build();
        openpgp.signClearMessage([this._privateKey], cleartext, onSigned);

        function onSigned(err, signedCleartext) {
            if (err) {
                callback(err);
                return;
            }

            var signatureHeader = '-----BEGIN PGP SIGNATURE-----';
            signatureNode = rootNode.createChild('application/pgp-signature');
            signatureNode.setContent(signatureHeader + signedCleartext.split(signatureHeader).pop());

            callback();
        }
    };

    PgpBuilder.prototype._createEncryptedMimeTree = function(plaintext, ciphertext, rootNode) {
        var ptNode, pgpNode, versionNode, ctNode;

        // creates an encrypted pgp/mime message
        // either pin the encrypted mime-subtree under the multipart/mixed node, OR 
        // create a top-level multipart/encrypted node

        // do we need to frame the encrypted message with a clear text?
        if (plaintext) {
            rootNode.setHeader('content-type', 'multipart/mixed');

            ptNode = rootNode.createChild('text/plain');
            ptNode.setContent(plaintext);

            // if we have a plain text node, we need a dedicated node that holds the pgp
            pgpNode = rootNode.createChild('multipart/encrypted');
        } else {
            // otherwise the node that holds the pgp is the root node
            rootNode.setHeader('multipart/encrypted');
            pgpNode = rootNode;
        }

        pgpNode.setHeader('content-description', 'OpenPGP encrypted message');
        pgpNode.setContent('This is an OpenPGP/MIME encrypted message.');

        // set the version info
        versionNode = pgpNode.createChild('application/pgp-encrypted');
        versionNode.setHeader('content-description', 'PGP/MIME Versions Identification');
        versionNode.setContent('Version: 1');

        // set the ciphertext
        ctNode = pgpNode.createChild('application/octet-stream');
        ctNode.setHeader('content-description', 'OpenPGP encrypted message');
        ctNode.setHeader('content-disposition', 'inline');
        ctNode.filename = 'encrypted.asc';
        ctNode.setContent(ciphertext);
    };

    return PgpBuilder;
});