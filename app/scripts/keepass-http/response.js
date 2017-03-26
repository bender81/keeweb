
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

module.exports = KeePassResponse;
