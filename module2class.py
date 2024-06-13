module2class = {
    'Buffer': 'buf',
    'buffer.Blob': 'blob',
    'Buffer.alloc': 'buf',
    'Buffer.allocUnsafe': 'buf',
    'Buffer.allocUnsafeSlow': 'buf',
    'Buffer.concat': 'buf',
    'Buffer.copyBytesFrom': 'buf',
    'Buffer.from': 'buf',
    'crypto.createCipheriv': 'cipher',
    'crypto.createDecipheriv': 'decipher',
    'crypto.createCipher': 'cipher',
    'crypto.createDecipher': 'decipher',
    'crypto.createHash': 'hash',
    'crypto.createHmac': 'hmac',
    'crypto.X509Certificate': 'x509',
    'crypto.createDiffieHellman': 'diffieHellman',
    'fsPromises.open': 'filehandle',
    'fs.openAsBlob': 'blob',
    'fs.opendir': 'dir',
    'fs.opendirSync': 'dir',
    'fsPromises.opendir': 'dir',
    'fs.watch': 'watcher',
    'fs.watchFile': 'watcher',
    'fs.createReadStream': 'readStream',
    'fs.stat': 'stats',
    'fs.lstat': 'stats',
    'fs.fstat': 'stats',
    'fs.createWriteStream': 'writeStream',
    'http.request': 'request',
    'https.request': 'request',
    'http.createServer': 'server',
    'https.createServer': 'server',
    'net.createServer': 'server',
    'net.createConnection': 'socket',
    'net.connect': 'socket',
    'net.Socket': 'socket',
    'dgram.createSocket': 'socket',
    'tls.createServer': 'server',
    'tls.connect': 'tlsSocket',
    'vm.Script': 'script',
    'events.EventEmitter': 'emitter'
}


def get_class(full_call_name: str):
    if full_call_name in module2class:
        return module2class[full_call_name]
    else:
        return None
