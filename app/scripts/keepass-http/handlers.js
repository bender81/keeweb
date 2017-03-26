'use strict';

const kdbxweb = require('kdbxweb');
const Protocol = require('./protocol');
const KeePassResponse = require('./response');
const ByteUtils = kdbxweb.ByteUtils;
const Launcher = require('../comp/launcher');
const Alerts = require('../comp/alerts');
const Timeouts = require('../const/timeouts');
const EntryModel = require('../models/entry-model')

const Logger = require('../util/logger');
const logger = new Logger('keepass-http.handlers');

const Handlers = {
    KEEPASSHTTP_UUID: 'NGl6QIpbQcCfNol9Yj7LMQ==',
    KEEPASSHTTP_NAME: 'KeePassHttp Settings',
    ASSOCIATE_KEY_PREFIX: 'AES Key: ',

    init(appModel) {
        this.appModel = appModel;
        return this;
    },

    handleHttpRequest(request, callback) {
        try {
            // const db = this.appModel.files.first().db;
            const groupUuid = ByteUtils.bytesToHex(this.appModel.files.first().get('groups').first().group.uuid.toBytes());
            const recycleBinUuid = ByteUtils.bytesToHex(this.appModel.files.first().getTrashGroup().group.uuid.toBytes());
            
            const hash = kdbxweb.CryptoEngine.sha256(groupUuid + recycleBinUuid).then((hash) => {
                const response = new KeePassResponse(request.RequestType, ByteUtils.bytesToHex(hash));
                response.Id = request.Id;
                const aes = kdbxweb.CryptoEngine.createAesCbc();

                try {
                    switch (request.RequestType) {
                        case 'test-associate':
                            this.testAssociate(request, response, aes, callback);
                            break;
                        case 'associate':
                            this.associate(request, response, aes, callback);
                            break;
                        case 'get-logins':
                            this.getLogins(request, response, aes, callback);
                            break;
                        default:
                            response.Error = "Unknown command: " + request.RequestType;
                            callback(response);
                            break;
                    }
                } catch (err) {
                    response.Error = err + "";
                    callback(response);
                    Alerts.error({
                        header: 'KeePassHttp Error',
                        body: '***BUG***' + err,
                        buttons: [],
                        esc: false, enter: false, click: false
                    });
                }
            });
        } catch (err) {
            const response = new KeePassResponse(request.RequestType, null);
            response.Error = err + "";
            callback(response);
        }
    },

    showSettingsLoadError() {
        Alerts.error({
            header: Locale.appSettingsError,
            body: Locale.appSettingsErrorBody,
            buttons: [],
            esc: false, enter: false, click: false
        });
    },

    GetConfigEntry(create) {
        const rootGroup = this.appModel.files.first().get('groups').first();
        const uuid = new kdbxweb.KdbxUuid(this.KEEPASSHTTP_UUID);

        let entry = rootGroup.file.getEntry(rootGroup.file.subId(uuid.id));
        if (!entry && create) {
            entry = EntryModel.newEntry(rootGroup, rootGroup.file);
            entry.entry.uuid = uuid;
            entry.entry.times.update();
            entry.entry.fields.Title = this.KEEPASSHTTP_NAME;
            entry.entry.fields.UserName = '';
            rootGroup.file.reload();
        }
        return entry;
    },

    testAssociate(request, response, aes, callback) {
        Protocol.verifyRequest(request, aes, (isValidRequest) => {
            if (!isValidRequest) {
                response.Success = false;
                callback(response);
            } else {
                response.Success = true;
                // response.Id = request.Id;
                Protocol.SetResponseVerifier(response, aes, callback);
            }
        });
    },

    associate(request, response, aes, callback) {
        Protocol.TestRequestVerifier(request, aes, request.Key, (isValidRequest) => {
            response.Success = false;
            if (!isValidRequest) {
                callback(response);
                return;
            }

            setTimeout(() => Launcher.showMainWindow(), Timeouts.RedrawInactiveWindow);
            this.ConfirmKeyAssociationDialog(request.Key, (entry, keyName) => {
                if(entry && keyName) {
                    entry.setField(this.ASSOCIATE_KEY_PREFIX + keyName, kdbxweb.ProtectedValue.fromString(request.Key));
                    entry.file.reload();
                    response.Success = true;
                    response.Id = keyName;
                    Protocol.SetResponseVerifier(response, aes, callback);
                } else {
                    callback(response);
                }
            });
        });
    }, 

    ConfirmKeyAssociationDialog(associationKey, callback) {
        Alerts.yesno({
            header: "KeePassHttp: Confirm New Key Association",
            input: "Key Id",
            click: null,
            body: associationKey + '<br /><br />' + '<p class="text-color">You have received an association request for the above key. ' 
                    + 'If you would like to allow this key access to your KeePass database, accept it.</p>',
            success: (res, keyName) => {
                const entry = this.GetConfigEntry(true);

                let conflictKey = false;
                _.forEach(entry.fields, function(value, field) {
                    const _keyName = this.ASSOCIATE_KEY_PREFIX + keyName;
                    if(field.toLowerCase() == _keyName.toLowerCase()) {
                        conflictKey = true;
                        Alerts.yesno({
                            header: "KeePassHttp: Overwrite existing key?",
                            click: null,
                            body: 'A shared encryption-key with the name "' + field + '" already exists. '
                                + '<br /><br />' + 'Do you want to overwrite it?',
                            success: () => {
                                callback(entry, keyName);
                            },
                            cancel: (res) => {
                                setTimeout(() => this.ConfirmKeyAssociationDialog(associationKey, callback), 1000);
                            }
                        });
                    }
                }, this);

                if(!conflictKey) {
                    callback(entry, keyName);
                }
            },
            cancel: (res) => {
                callback();
            }
        });
    },

    getLogins(request, response, aes, callback) {
        Protocol.verifyRequest(request, aes, (isValidRequest) => {
            if (!isValidRequest) {
                response.Success = false;
                callback(response);
            } else {
                response.Success = true;
                // response.Id = request.Id;
                Protocol.SetResponseVerifier(response, aes, callback);
            }
        });
    }

};

module.exports = Handlers;
