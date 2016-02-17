'use strict';
if (typeof exports === 'object' && typeof define !== 'function') {
    var define = function(factory) {
        module.exports = factory(require, exports, module);
    };
}

define(function(require) {
    var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('openpgp'),
        Mailbuild = require('emailjs-mime-builder'),
        PgpBuilder;

    /**
     * Constructor for the PGP builder
     * @param {String} pgpWorkerPath The path to the openpgp async source initialize a Wek Worker
     */
    PgpBuilder = function(options, pgp) {
        options = options || {};
        this._pgp = pgp || openpgp;
        this._pgpKey = this._pgp.key; // get key module
        this._pgp = this._pgp.default; // get ES6 default module

        // set pgp worker path for in browser use
        if (typeof window !== 'undefined' && window.Worker && options.pgpWorkerPath) {
            this._pgp.initWorker({ path:options.pgpWorkerPath });
        }
    };

    /**
     * Set the private key used to sign your messages
     * @param {String} options.privateKey ASCII-armored private key to sign the messages
     * @param {String} options.passphrase The passphrase to encrypt options.armoredPrivateKey
     *
     * @return {Promise}
     */
    PgpBuilder.prototype.setPrivateKey = function(options) {
        var self = this;

        return new Promise(function(resolve) {
            // decrypt the private key (for signing)
            var privateKey = self._pgpKey.readArmored(options.privateKeyArmored).keys[0];
            if (!privateKey.decrypt(options.passphrase)) {
                throw new Error('Wrong passphrase! Could not decrypt the private key!');
            }

            self._privateKey = privateKey;
            resolve();
        }).catch(function(error) {
            throw new Error('Could not parse armored private key! ' + error.message); // rethrow with descriptive error
        });
    };

    /**
     * Creates a signed MIME-tree and encrypts it. Attaches an encrypted = true flag to options.mail if successful.
     * @param {String} options.mail.body Plain text body to be sent with the mail
     * @param {Array} options.mail.attachments (optional) Array of attachment objects with filename {String}, content {Uint8Array}, and mimeType {String}
     * @param {Array} options.publicKeysArmored The public keys with which the message should be encrypted
     *
     * @return {Promise<mail>} Invoked when the mail has been encrypted.
     */
    PgpBuilder.prototype.encrypt = function(options) {
        var self = this;

        if (!this._privateKey) {
            return new Promise(function() {
                throw new Error('No private key has been set. Cannot sign mails!');
            });
        }

        options.mail.attachments = options.mail.attachments || [];

        var rootNode = options.rootNode || new Mailbuild();

        // create the signed mime tree
        return self._createSignedMimeTree(options.mail, rootNode).then(function() {
            var plaintext = rootNode.build(),
                publicKeys = [];

            // parse the ASCII-armored public keys to encrypt the signed mime tree
            options.publicKeysArmored.forEach(function(key) {
                publicKeys.push(self._pgpKey.readArmored(key).keys[0]);
            });

            // encrypt the signed mime tree
            return self._pgp.encrypt({ publicKeys:publicKeys, privateKeys:self._privateKey, data:plaintext });
        }).then(function(ciphertext) {
            // replace the mail body with the ciphertext and empty the attachment
            // (attachment is now within the ciphertext!)
            options.mail.encrypted = true;
            options.mail.body = ciphertext.data;
            options.mail.attachments.length = 0;
            options.mail.bodyParts = [{
                type: 'encrypted',
                content: ciphertext.data
            }];

            return options.mail;
        });
    };

    /**
     * Builds the complete encrypted RFC message to be sent via SMTP. It is necessary to call encrypt() before.
     * @param {Object} options.mail.from Array containing one object with the ASCII string representing the sender address, e.g. 'foo@bar.io'
     * @param {String} options.mail.body PGP-Encrypted mail body
     * @param {Array} options.mail.to (optional) Array of ASCII strings representing the recipient (e.g. ['the.dude@lebowski.com', 'donny@kerabatsos.com'])
     * @param {Array} options.mail.cc (optional) Array of ASCII strings representing the recipient, see mail.to
     * @param {Array} options.mail.bcc (optional) Array of ASCII strings representing the recipient, see mail.to
     * @param {String} options.mail.subject String containing with the mail's subject
     * @param {String} options.mail.headers Object custom headers to add to the message header
     *
     * @return {Promise<rfcMessage, smtpInfo>} Invoked when the mail has been built and the smtp information has been created.
     */
    PgpBuilder.prototype.buildEncrypted = function(options) {
        var self = this;

        // only build the encrypted rfc message for mails that have been encrypted before...
        return new Promise(function(resolve) {
            if (!self._privateKey) {
                throw new Error('No private key has been set. Cannot sign mails!');
            }

            // create the PGP/MIME tree
            var rootNode = options.rootNode || new Mailbuild();
            self._createEncryptedMimeTree(options.mail.bodyParts[0].content, rootNode);
            self._setEnvelope(options.mail, rootNode); // configure the envelope
            resolve({
                rfcMessage: rootNode.build(),
                smtpInfo: rootNode.getEnvelope()
            });
        });
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
     *
     * @return {Promise<rfcMessage, smtpInfo>} Invoked when the mail has been built and the smtp information has been created.
     */
    PgpBuilder.prototype.buildSigned = function(options) {
        var self = this;

        if (!this._privateKey) {
            return new Promise(function() {
                throw new Error('No private key has been set. Cannot sign mails!');
            });
        }

        var rootNode = options.rootNode || new Mailbuild();

        // create a signed mime tree
        return self._createSignedMimeTree(options.mail, rootNode).then(function() {
            self._setEnvelope(options.mail, rootNode); // configure the envelope data
            return {
                rfcMessage: rootNode.build(),
                smtpInfo: rootNode.getEnvelope()
            };
        });
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

        // set custom headers
        if (mail.headers) {
            rootNode.setHeader(mail.headers);
        }
    };

    PgpBuilder.prototype._createSignedMimeTree = function(mail, rootNode) {
        var contentNode, textNode, cleartext;

        //
        // create the mime tree
        //

        mail.bodyParts = [{
            type: 'signed',
            content: []
        }];
        var signedBodyPartRoot = mail.bodyParts[0].content;

        rootNode.setHeader('content-type', 'multipart/signed; micalg=pgp-sha256; protocol=application/pgp-signature');

        // this a plain text mail? then only one text/plain node is needed
        if (!mail.attachments || mail.attachments.length === 0) {
            contentNode = rootNode.createChild('text/plain');
            contentNode.setHeader('content-transfer-encoding', 'quoted-printable');
            contentNode.setContent(mail.body);
            signedBodyPartRoot.push({
                type: 'text',
                content: mail.body
            });
        } else {
            // we have attachments, so let's create a multipart/mixed mail
            contentNode = rootNode.createChild('multipart/mixed');

            // create the text/plain node
            textNode = contentNode.createChild('text/plain');
            textNode.setHeader('content-transfer-encoding', 'quoted-printable');
            textNode.setContent(mail.body);
            signedBodyPartRoot.push({
                type: 'text',
                content: mail.body
            });

            // add the attachments
            mail.attachments.forEach(function(attmtObj) {
                var mimeType = 'application/octet-stream';
                var attmtNode = contentNode.createChild(mimeType);
                attmtNode.setHeader('content-transfer-encoding', 'base64');
                attmtNode.filename = attmtObj.filename;
                attmtNode.setContent(attmtObj.content);
                signedBodyPartRoot.push({
                    type: 'attachment',
                    mimeType: mimeType,
                    filename: attmtObj.filename,
                    content: attmtObj.content
                });
            });
        }

        //
        // Sign the whole thing
        //

        cleartext = contentNode.build();
        return this._pgp.sign({ privateKeys:[this._privateKey], data:cleartext }).then(function(signedCleartext) {
            var signatureHeader = '-----BEGIN PGP SIGNATURE-----';
            var signature = signatureHeader + signedCleartext.data.split(signatureHeader).pop();
            var signatureNode = rootNode.createChild('application/pgp-signature');
            signatureNode.setHeader('content-transfer-encoding', '7bit');
            signatureNode.setContent(signature);

            signedBodyPartRoot.message = cleartext;
            signedBodyPartRoot.signature = signature;
        });
    };

    PgpBuilder.prototype._createEncryptedMimeTree = function(ciphertext, rootNode) {
        // creates an encrypted pgp/mime message with a top-level multipart/encrypted node
        rootNode.setHeader('content-type', 'multipart/encrypted; protocol=application/pgp-encrypted');
        rootNode.setHeader('content-description', 'OpenPGP encrypted message');
        rootNode.setHeader('content-transfer-encoding', '7bit');
        rootNode.setContent('This is an OpenPGP/MIME encrypted message.');

        // set the version info
        var versionNode = rootNode.createChild('application/pgp-encrypted');
        versionNode.setHeader('content-description', 'PGP/MIME Versions Identification');
        versionNode.setHeader('content-transfer-encoding', '7bit');
        versionNode.setContent('Version: 1');

        // set the ciphertext
        var ctNode = rootNode.createChild('application/octet-stream');
        ctNode.setHeader('content-description', 'OpenPGP encrypted message');
        ctNode.setHeader('content-disposition', 'inline');
        ctNode.setHeader('content-transfer-encoding', '7bit');
        ctNode.filename = 'encrypted.asc';
        ctNode.setContent(ciphertext);
    };

    return PgpBuilder;
});