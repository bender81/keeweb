'use strict';

const Backbone = require('backbone');
const AppSettingsModel = require('../models/app-settings-model');
const Launcher = require('../comp/launcher');
const Timeouts = require('../const/timeouts');

const Logger = require('../util/logger');
const logger = new Logger('keepass-http');

const Handlers = require('./handlers');

const KeePassHttp = {
    enabled: !!Launcher,

    init(appModel) {
        if (!this.enabled) {
            return;
        }
        logger.info('Initializing KeePassHttp');
        Launcher.openDevTools();

        Backbone.on('http-request', this.handleHttpRequest, this);

        if (AppSettingsModel.instance.get('keePassHttpServer')) {
            Launcher.startKeePassHttpServer(this);
        }

        this.appModel = appModel;
        Handlers.init(this.appModel);
        return this;
    },

    processPendingEvent() {
        if (!this.pendingEvent) {
            return;
        }
        logger.debug('processing pending KeePassHttp event');
        const evt = this.pendingEvent;
        this.appModel.files.off('update', this.processPendingEvent, this);
        this.pendingEvent = null;
        this.handleHttpRequest(evt);
    },

    handleHttpRequest(keePassReq) {
        if (!this.appModel.files.hasOpenFiles()) {
            this.pendingEvent = keePassReq;
            this.appModel.files.once('update', this.processPendingEvent, this);
            logger.debug('KeePassHttp event delayed');
            setTimeout(() => Launcher.showMainWindow(), Timeouts.RedrawInactiveWindow);
            return;
        }

        const request = keePassReq.request;
        Handlers.handleHttpRequest(request, (response) => {
            keePassReq.response = response;
            keePassReq.status = 'finished';

            let ipcRenderer = Launcher.electron().ipcRenderer;
            ipcRenderer.send('keepasshttp-status-message', keePassReq);
        });
    }
};

module.exports = KeePassHttp;
