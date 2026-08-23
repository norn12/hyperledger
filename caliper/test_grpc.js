const grpc = require('@grpc/grpc-js');
const fs = require('fs');
const path = require('path');

const PEM = `-----BEGIN CERTIFICATE-----
MIICcDCCAhegAwIBAgIQGkxTtbiGYMsrkIjc08D4uDAKBggqhkjOPQQDAjCBgjEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
cmFuY2lzY28xHzAdBgNVBAoTFmhvc3BpdGFsLnplcm90cnVzdC5jb20xJTAjBgNV
BAMTHHRsc2NhLmhvc3BpdGFsLnplcm90cnVzdC5jb20wHhcNMjYwNDA0MTQwNjAw
WhcNMzYwNDAxMTQwNjAwWjCBgjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlm
b3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHzAdBgNVBAoTFmhvc3BpdGFs
Lnplcm90cnVzdC5jb20xJTAjBgNVBAMTHHRsc2NhLmhvc3BpdGFsLnplcm90cnVz
dC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATr46zDfxlOTbx5NHM8oAlW
OPLXjwQbz13W0WvfYb2Laj6C2GDwz1CTuM7gD6MmwhGhH1x230KWaywuIPy6E4to
o20wazAOBgNVHQ8BAf8EBAMCAaYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUF
BwMBMA8GA1UdEwEB/wQFMAMBAf8wKQYDVR0OBCIEIB4RjngdHTM/VWUQ4OOPWept
dZamC0/nhqQmjV3YVqNwMAoGCCqGSM49BAMCA0cAMEQCIDtmo3b7nA+zhYfobanl
IyVY/XLLgyOcQUXyC2HRio2HAiAr+vwpVuLPsowmCyHdk0v0KFoPwtXm3Qra0SF4
ZI9qLw==
-----END CERTIFICATE-----`;

const credentials = grpc.credentials.createSsl(Buffer.from(PEM));
const options = {
    'grpc.ssl_target_name_override': 'peer0.hospital.zerotrust.com',
    'grpc.default_authority': 'peer0.hospital.zerotrust.com'
};

console.log('--- ZeroTrustBlock gRPC Diagnostic ---');
console.log('Attempting to connect to 127.0.0.1:7051 (Hospital Peer)...');

const client = new grpc.Client('127.0.0.1:7051', credentials, options);

const deadline = new Date();
deadline.setSeconds(deadline.getSeconds() + 5);

client.waitForReady(deadline, (err) => {
    if (err) {
        console.error(`[FAILURE] Connection timed out: ${err.message}`);
        console.error('Possible reasons: Port closed, SAN mismatch, or TLS Root mismatch.');
        process.exit(1);
    } else {
        console.log('[SUCCESS] gRPC Secure Channel Established!');
        console.log('Node.js can reach the ZeroTrustBlock ledger.');
        process.exit(0);
    }
});
