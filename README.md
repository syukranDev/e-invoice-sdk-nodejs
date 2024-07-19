# einvoice-sdk-nodejs

A Node.js SDK for interacting with e-invoice APIs using JSON format data, including obtaining tokens, submitting documents, and managing e-invoice data.

## Features

- Obtain tokens as a taxpayer or intermediary
- Submit documents as an intermediary
- Get document details
- Cancel valid documents by supplier
- Utility functions for JSON to Base64 conversion, SHA256 hash calculation, and generating certificate hashed parameters
- Auto API recall if it hit API Rate Limit

## Installation

```bash
npm install
```

## Usage
-Create a .env file in the root directory and add your configuration variables:
```bash
CLIENT_ID_VALUE=your-client-id
CLIENT_SECRET_1_VALUE=your-client-secret
PREPROD_BASE_URL=your-preprod-base-url
X509Certificate_VALUE=your-x509-certificate
X509SubjectName_VALUE=your-x509-subject-name
X509IssuerName_VALUE=your-x509-issuer-name
X509SerialNumber_VALUE=your-x509-serial-number
PRIVATE_KEY_FILE_PATH=example.key
PRIVATE_CERT_FILE_PATH=exampleCert.crt
```

```bash
const { getTokenAsTaxPayer, submitDocumentAsIntermediary } = require('./einvoice-sdk.js');

# Note: You may refer getCertificatesHashedParams() on how to generate hashed signed documents.
# let hashed_payload = {
#     "documents": [
#          {
#             "format": "JSON",
#             "documentHash": <sha256_encoded_signed_documents>,
#             "codeNumber": "",
#             "document": <base64_encoded_signed_documents>
#         } 
        
#     ]
# }

async function exampleUsage() {
  try {
    const token = await getTokenAsTaxPayer();
    const documentSubmissionResponse = await submitDocumentAsIntermediary(hashed_payload, token.access_token);
    console.log(documentSubmissionResponse);
  } catch (error) {
    console.error(error);
  }
}

exampleUsage();
```

## Contributing / License
-This project is licensed under the ISC License.

