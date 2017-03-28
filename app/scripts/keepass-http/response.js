
const KeePassResponse = function(requestType, hash) {
    this.Count = null;
    this.Entries = null;
    this.Error = null;
    this.Hash = hash;
    this.Id = '';
    this.Nonce = '';
    this.RequestType = requestType;
    this.Success = false;
    this.Verifier = '';
    this.Version = '1.8.4.1';
    this.objectName = '';
};

const KeePassResponseEntry = function(name, login, password, uuid, stringFields) {
    this.Login = login;
    this.Password = password;
    this.Uuid = uuid;
    this.Name = name;
    this.StringFields = stringFields;
};

const KeePassResponseStringField = function (key, value) {
    this.Key = key;
    this.Value = value;
};

module.exports = KeePassResponse;
module.exports.KeePassResponseEntry = KeePassResponseEntry;
module.exports.KeePassResponseStringField = KeePassResponseStringField;
