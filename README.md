# einvoice-sdk-nodejs

A Node.js SDK for interacting with e-invoice APIs, including obtaining tokens, submitting documents, and managing e-invoice data.

## Features

- Obtain tokens as a taxpayer or intermediary
- Submit documents as an intermediary
- Get document details
- Cancel valid documents by supplier
- Utility functions for JSON to Base64 conversion, SHA256 hash calculation, and generating certificate hashed parameters

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

```

```bash
const { getTokenAsTaxPayer, submitDocumentAsIntermediary } = require('./path-to-your-sdk');

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

