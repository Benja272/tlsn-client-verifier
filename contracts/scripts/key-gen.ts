import { Buffer } from 'buffer';
import { createPublicKey } from 'crypto';

// The PEM-encoded public key string you provided
const PEM_PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MDYwEAYHKoZIzj0CAQYFK4EEAAoDIgADe0jxnBObaIj7Xjg6TXLCM1GG/VhY5650
OrS/jgcbBuc=
-----END PUBLIC KEY-----
`;

function convertPemToCompressedHex(pemKey: string): string {
    // 1. Create a KeyObject from the PEM string using Node's crypto module
    // The key format is implicitly handled by createPublicKey()
    const keyObject = createPublicKey({
        key: pemKey,
        format: 'pem',
    });

    // 2. Export the key in 'der' format, which gives us the raw EC key data (SPKI)
    const spkiDer = keyObject.export({
        format: 'der',
        type: 'spki',
    });

    // 3. The raw SECP256K1 public key is the last 66 bytes of the SPKI DER structure.
    // This includes the 0x04 prefix (for uncompressed) followed by the 64 bytes of the X and Y coordinates.
    // For this specific SPKI structure for SECP256K1, the header is 29 bytes long.
    // The raw key data starts at index 29.
    const RAW_KEY_START_INDEX = 29;
    
    // The raw uncompressed public key (0x04 || X || Y)
    const rawUncompressedPubkey = spkiDer.subarray(RAW_KEY_START_INDEX);

    // 4. Extract the X-coordinate (bytes 1 through 32 of the uncompressed key)
    // The uncompressed key starts with 0x04, so X is from index 1 to 33.
    const xCoordinate = rawUncompressedPubkey.subarray(1, 33); 
    
    // 5. Determine the compression prefix (0x02 or 0x03) from the Y-coordinate.
    // The Y-coordinate is the last byte of the raw uncompressed key (index 33 to 65).
    // The prefix is '0x02' if the last byte of Y is even, and '0x03' if odd.
    const yByte = rawUncompressedPubkey[rawUncompressedPubkey.length - 1];
    const prefix = (yByte % 2 === 0) ? Buffer.from([0x02]) : Buffer.from([0x03]);
    
    // 6. Combine the prefix (0x02/0x03) with the X-coordinate.
    const compressedKeyBuffer = Buffer.concat([prefix, xCoordinate]);
    
    // 7. Convert to the final 0x-prefixed hex string
    return '0x' + compressedKeyBuffer.toString('hex');
}

async function main() {
    try {
        const compressedHex = convertPemToCompressedHex(PEM_PUBLIC_KEY);

        console.log("-----------------------------------------");
        console.log("  ✅ PEM Public Key Converted to Compressed Hex  ");
        console.log("-----------------------------------------");
        console.log(`Input PEM Block:\n${PEM_PUBLIC_KEY.trim()}`);
        console.log(`Output Compressed Hex (33 bytes):`);
        console.log(compressedHex);
        console.log("-----------------------------------------");
        
        // This is the desired format for your constant
        const trustedNotaryPubkey = compressedHex;
        console.log(`TypeScript Constant: const trustedNotaryPubkey = "${trustedNotaryPubkey}";`);
        
    } catch (error) {
        console.error("Error during key conversion:", error);
    }
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });