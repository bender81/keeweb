'use strict';

const AppSettingsModel = require('../models/app-settings-model');
const kdbxweb = require('kdbxweb');
const ByteUtils = kdbxweb.ByteUtils;
// const CryptoHelper = require('./crypto-helper');

const Logger = require('../util/logger');
const logger = new Logger('keepass-http');

const Protocol = {

    init(handlers) {
        this.handlers = handlers;
    },

    verifyRequest: function (request, aes, callback) {
        const entry = this.handlers.GetConfigEntry(false);
        if (entry == null) {
            callback(false);
            return;
        }
        const s = entry.fields[this.handlers.ASSOCIATE_KEY_PREFIX + request.Id];
        if (s == null) {
            callback(false);
            return;
        }

        this.TestRequestVerifier(request, aes, s.getText(), callback);
    },

    TestRequestVerifier: function (request, aes, key, callback) {
        const crypted = ByteUtils.base64ToBytes(request.Verifier);
        // logger.info('crypted', Array.apply([], crypted).join(","));

        aes.Key = ByteUtils.base64ToBytes(key);
        // logger.info('Key', Array.apply([], aes.Key).join(","));
        aes.IV = ByteUtils.base64ToBytes(request.Nonce);
        // logger.info('IV', Array.apply([], aes.IV).join(','));

        aes.importKey(aes.Key).then(() => {
            aes.decrypt(crypted, aes.IV).then(result => {
                // logger.info('result', Array.apply([], new Uint8Array(result)).join(","));
                // logger.info('ByteUtils.bytesToString(result) == request.Nonce => ', ByteUtils.bytesToString(result) === request.Nonce);
                callback(ByteUtils.bytesToString(result) === request.Nonce);
            });
        });
    },

    SetResponseVerifier: function (response, aes, callback) {
        aes.IV = kdbxweb.Random.getBytes(16);
        response.Nonce = ByteUtils.bytesToBase64(aes.IV);
        this.CryptoTransform(response.Nonce, false, true, aes, 'ENCRYPT', (Verifier) => {
            response.Verifier = Verifier;
            callback(response);
        });
    },

    CryptoTransform: function(input, base64in, base64out, aes, mode, callback) {
        let bytes;
        if (base64in) {
            bytes = ByteUtils.base64ToBytes(input);
        } else {
            bytes = ByteUtils.stringToBytes(input);
        }

        const transformResult = function(buf) {
            callback(base64out ? ByteUtils.bytesToBase64(buf) : ByteUtils.bytesToString(buf));
        };

        if (mode === 'ENCRYPT') {
            aes.encrypt(bytes, aes.IV).then(transformResult);
        } else if (mode === 'DECRYPT') {
            aes.decrypt(bytes, aes.IV).then(transformResult);
        }
    }

};

module.exports = Protocol;
