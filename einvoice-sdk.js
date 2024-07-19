//DEV Note: Committing here for dev testing, please dont remove.
const path = require('path')
const axios = require('axios');
const CryptoJS = require('crypto-js');
const env = process.env.NODE_ENV || 'dev';
const conf = require('../config/config.json')[env];
const db = require('../model/db.js');
const Op = db.Sequelize.Op;
const sq = db.sequelize;
const fs = require('fs');
const forge = require('node-forge');
const jsonminify = require('jsonminify');
const crypto = require('crypto');
require('dotenv').config();

let httpOptions = {
        client_id: process.env.CLIENT_ID_VALUE,
        client_secret: process.env.CLIENT_SECRET_1_VALUE,
        grant_type: 'client_credentials',
        scope: 'InvoicingAPI'
}

async function getTokenAsTaxPayer(tenant_id) {
  try {

    const response = await axios.post(`${process.env.PREPROD_BASE_URL}/connect/token`, httpOptions, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    if(response.status == 200) return response.data;
  } catch (err) {
    if (err.response.status == 429) {
      console.log('A- Current iteration hitting Rate Limit 429 of LHDN Taxpayer Token API, retrying...')
      const rateLimitReset = err.response.headers["x-rate-limit-reset"];

      if (rateLimitReset) {
        const resetTime = new Date(rateLimitReset).getTime();
        const currentTime = Date.now();
        const waitTime = resetTime - currentTime;

        if (waitTime > 0) {
          console.log('=======================================================================================');
          console.log('              LHDN Taxpayer Token API hitting rate limit HTTP 429                  ');
          console.log(`              Refetching................. (Waiting time: ${waitTime} ms)                  `);
          console.log('=======================================================================================');
          await new Promise(resolve => setTimeout(resolve, waitTime));
          return await getTokenAsTaxPayer();
        }            
      }
    } else {
      throw new Error(`Failed to get token: ${err.message}`);
    }
  }
}

async function getTokenAsIntermediary() {
  try {
    let config = await getClientConfig(tenant_id);

    const response = await axios.post(`${process.env.PREPROD_BASE_UR}/connect/token`, httpOptions, {
      headers: {
        'onbehalfof':config.configDetails.tin,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    if(response.status == 200) return response.data;
  } catch (err) {
    if (err.response.status == 429) {
      console.log('A- Current iteration hitting Rate Limit 429 of LHDN Intermediary Token API, retrying...')
      const rateLimitReset = err.response.headers["x-rate-limit-reset"];

      if (rateLimitReset) {
        const resetTime = new Date(rateLimitReset).getTime();
        const currentTime = Date.now();
        const waitTime = resetTime - currentTime;

        if (waitTime > 0) {
          console.log('=======================================================================================');
          console.log('              LHDN Intermediary Token API hitting rate limit HTTP 429                  ');
          console.log(`              Refetching................. (Waiting time: ${waitTime} ms)                  `);
          console.log('=======================================================================================');
          await new Promise(resolve => setTimeout(resolve, waitTime));
          return await getTokenAsIntermediary();
        }            
      }
    } else {
      throw new Error(`Failed to get token: ${err.message}`);
    }
  }
}

async function submitDocumentAsIntermediary(docs, token) {
    try {
        const payload = {
            documents: docs
        };
        
        const response = await axios.post(`${process.env.PREPROD_BASE_UR}/api/v1.0/documentsubmissions`, payload, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });

        return { status: 'success', data: response.data };
    } catch (err) {
        if (err.response.status == 429) {
            const rateLimitReset = err.response.headers["x-rate-limit-reset"];
            if (rateLimitReset) {
            const resetTime = new Date(rateLimitReset).getTime();
            const currentTime = Date.now();
            const waitTime = resetTime - currentTime;
            
            console.log('=======================================================================================');
            console.log('              LHDN SubmitDocument API hitting rate limit HTTP 429                      ');
            console.log('                 Retrying for current iteration.................                       ');
            console.log(`                     (Waiting time: ${waitTime} ms)                                       `);
            console.log('=======================================================================================');

            if (waitTime > 0) {
                await new Promise(resolve => setTimeout(resolve, waitTime));
                return await submitDocumentAsIntermediary(docs, token)
            }            
            }
        }

        if (err.response.status == 500) {
            throw new Error('External LHDN SubmitDocument API hitting 500 (Internal Server Error). Please contact LHDN support.')
        }
        
        if (err.response.status == 400){
            return { status: 'failed', error: err.response.data };
        }  else {
            return { status: 'failed', error: err.response.data };;
        }        
    }
}

async function getDocumentDetails(irb_uuid, token) {
  try {
          const response = await axios.get(`${process.env.PREPROD_BASE_UR}/api/v1.0/documents/${irb_uuid}/details`, {
              headers: {
                  // 'Content-Type': 'application/json',
                  'Authorization': `Bearer ${token}`
              }
          });

          return { status: 'success', data: response.data };
  } catch (err) {
          if (err.response.status == 429) {
            const rateLimitReset = err.response.headers["x-rate-limit-reset"];
            if (rateLimitReset) {
              const resetTime = new Date(rateLimitReset).getTime();
              const currentTime = Date.now();
              const waitTime = resetTime - currentTime;
              
              console.log('=======================================================================================');
              console.log('              LHDN DocumentDetails API hitting rate limit HTTP 429                      ');
              console.log('                 Retrying for current iteration.................                       ');
              console.log(`                     (Waiting time: ${waitTime} ms)                                       `);
              console.log('=======================================================================================');

              if (waitTime > 0) {
                await new Promise(resolve => setTimeout(resolve, waitTime));
                return await getDocumentDetails(docs, token)
              }            
            }
          } else {
            // throw new Error(`Failed to get IRB document details for document UUID ${irb_uuid}: ${err.message}`);       
            console.error(`Failed to get IRB document details for document UUID ${irb_uuid}:`, err.message);
            throw err; 
          }
  }
}

async function cancelValidDocumentBySupplier(irb_uuid, cancellation_reason, token) {
  let payload = {
    status: 'cancelled',
    reason: cancellation_reason ? cancellation_reason : 'NA'
  }

  try {
    const response = await axios.put(`${process.env.PREPROD_BASE_UR}/api/v1.0/documents/state/${irb_uuid}/state`,
      payload, 
      {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        }
      }
    );

    return { status: 'success', data: response.data };
  } catch (err) {
    if (err.response.status == 429) {
      const rateLimitReset = err.response.headers["x-rate-limit-reset"];
      if (rateLimitReset) {
        const resetTime = new Date(rateLimitReset).getTime();
        const currentTime = Date.now();
        const waitTime = resetTime - currentTime;
        
        console.log('=======================================================================================');
        console.log('              LHDN Cancel Document API hitting rate limit HTTP 429                      ');
        console.log('                 Retrying for current iteration.................                       ');
        console.log(`                     (Waiting time: ${waitTime} ms)                                       `);
        console.log('=======================================================================================');

        if (waitTime > 0) {
          await new Promise(resolve => setTimeout(resolve, waitTime));
          return await cancelValidDocumentBySupplier(docs, token)
        }            
      }
    } else {
      // throw new Error(`Failed to get IRB document details for document UUID ${irb_uuid}: ${err.message}`);       
      console.error(`Failed to cancel document for IRB UUID ${irb_uuid}:`, err.message);
      throw err; 
    }
  }
}

function jsonToBase64(jsonObj) {
    const jsonString = JSON.stringify(jsonObj);
    const base64String = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(jsonString));
    return base64String;
}

function calculateSHA256(jsonObj) {
    const jsonString = JSON.stringify(jsonObj);
    const hash = CryptoJS.SHA256(jsonString);
    return hash.toString(CryptoJS.enc.Hex);
}

function getCertificatesHashedParams(documentJson) {
  //Note: Supply your JSON without Signature and UBLExtensions
  let jsonStringifyData = JSON.stringify(documentJson)
  const minifiedJsonData = jsonminify(jsonStringifyData);

  const sha256Hash = crypto.createHash('sha256').update(minifiedJsonData, 'utf8').digest('base64');
  const docDigest = sha256Hash;

  const privateKeyPath = path.join(__dirname, 'eInvoiceCertificates', 'private_amast_keyless.key');
  const certificatePath = path.join(__dirname, 'eInvoiceCertificates', 'amast_cert.crt');

  const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
  const certificatePem = fs.readFileSync(certificatePath, 'utf8'); 

  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

  const md = forge.md.sha256.create();
  //NOTE DEV: 12/7/2024 - sign the raw json instead of hashed json
  // md.update(docDigest, 'utf8'); //disable this (no longer work)
  md.update(minifiedJsonData, 'utf8'); //enable this
  const signature = privateKey.sign(md);
  const signatureBase64 = forge.util.encode64(signature);

  // =============================================================
  // Calculate cert Digest
  // =============================================================
  const certificate = forge.pki.certificateFromPem(certificatePem);
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes();

  const sha256 = crypto.createHash('sha256').update(derBytes, 'binary').digest('base64');
  const certDigest = sha256;

  // =============================================================
  // Calculate the signed properties section digest
  // =============================================================
  let signingTime = new Date().toISOString()
  let signedProperties = 
  {
    "Target": "signature",
    "SignedProperties": [
      {
        "Id": "id-xades-signed-props",  
        "SignedSignatureProperties": [
            {
              "SigningTime": [
                {
                  "_": signingTime
                }
              ],
              "SigningCertificate": [
                {
                  "Cert": [
                    {
                      "CertDigest": [
                        {
                          "DigestMethod": [
                            {
                              "_": "",
                              "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
                            }
                          ],
                          "DigestValue": [
                            {
                              "_": certDigest
                            }
                          ]
                        }
                      ],
                      "IssuerSerial": [
                        {
                          "X509IssuerName": [
                            {
                              "_": "C=MY, O=Raffcomm Technologies Sdn Bhd, OU=1000449-W, CN=CypherSign Pro Max"
                            }
                          ],
                          "X509SerialNumber": [
                            {
                              "_": "528542416703086034"
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
      }
    ]
  }
  
  const signedpropsString = JSON.stringify(signedProperties);
  const signedpropsHash = crypto.createHash('sha256').update(signedpropsString, 'utf8').digest('base64');

  // return ({
  //     docDigest, // docDigest
  //     signatureBase64, // sig,
  //     certDigest,
  //     signedpropsHash, // propsDigest
  //     signingTime
  // })

  let certificateJsonPortion_Signature = [
      {
          "ID": [
            {
                "_": "urn:oasis:names:specification:ubl:signature:Invoice"
            }
          ],
          "SignatureMethod": [
            {
                "_": "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
            }
          ]
      }
  ]

  let certificateJsonPortion_UBLExtensions = [
    {
      "UBLExtension": [
        {
          "ExtensionURI": [
            {
              "_": "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
            }
          ],
          "ExtensionContent": [
            {
              "UBLDocumentSignatures": [
                {
                  "SignatureInformation": [
                    {
                      "ID": [
                        {
                          "_": "urn:oasis:names:specification:ubl:signature:1"
                        }
                      ],
                      "ReferencedSignatureID": [
                        {
                          "_": "urn:oasis:names:specification:ubl:signature:Invoice"
                        }
                      ],
                      "Signature": [
                        {
                          "Id": "signature",
                          "SignedInfo": [
                            {
                              "SignatureMethod": [
                                {
                                  "_": "",
                                  "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                                }
                              ],
                              "Reference": [
                                {
                                  "Id": "id-doc-signed-data",
                                  "URI": "",
                                  "DigestMethod": [
                                    {
                                      "_": "",
                                      "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
                                    }
                                  ],
                                  "DigestValue": [
                                    {
                                      "_": docDigest
                                    }
                                  ]
                                },
                                {
                                  "Id": "id-xades-signed-props",
                                  "Type": "http://uri.etsi.org/01903/v1.3.2#SignedProperties",
                                  "URI": "#id-xades-signed-props",
                                  "DigestMethod": [
                                    {
                                      "_": "",
                                      "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
                                    }
                                  ],
                                  "DigestValue": [
                                    {
                                      "_": signedpropsHash
                                    }
                                  ]
                                }
                              ]
                            }
                          ],
                          "SignatureValue": [
                            {
                              "_": signatureBase64
                            }
                          ],
                          "KeyInfo": [
                            {
                              "X509Data": [
                                {
                                  "X509Certificate": [
                                    {
                                      "_": process.env.X509Certificate_VALUE
                                    }
                                  ],
                                  "X509SubjectName": [
                                    {
                                      "_": process.env.X509SubjectName_VALUE
                                    }
                                  ],
                                  "X509IssuerSerial": [
                                    {
                                      "X509IssuerName": [
                                        {
                                          "_": process.env.X509IssuerName_VALUE
                                        }
                                      ],
                                      "X509SerialNumber": [
                                        {
                                          "_": process.env.X509SerialNumber_VALUE
                                        }
                                      ]
                                    }
                                  ]
                                }
                              ]
                            }
                          ],
                          "Object": [
                            {
                              "QualifyingProperties": [
                                {
                                  "Target": "signature",
                                  "SignedProperties": [
                                    {
                                      "Id": "id-xades-signed-props",
                                      "SignedSignatureProperties": [
                                        {
                                          "SigningTime": [
                                            {
                                              "_": signingTime
                                            }
                                          ],
                                          "SigningCertificate": [
                                            {
                                              "Cert": [
                                                {
                                                  "CertDigest": [
                                                    {
                                                      "DigestMethod": [
                                                        {
                                                          "_": "",
                                                          "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
                                                        }
                                                      ],
                                                      "DigestValue": [
                                                        {
                                                          "_": certDigest
                                                        }
                                                      ]
                                                    }
                                                  ],
                                                  "IssuerSerial": [
                                                    {
                                                      "X509IssuerName": [
                                                        {
                                                          "_": process.env.X509IssuerName_VALUE
                                                        }
                                                      ],
                                                      "X509SerialNumber": [
                                                        {
                                                          "_": process.env.X509SerialNumber_VALUE
                                                        }
                                                      ]
                                                    }
                                                  ]
                                                }
                                              ]
                                            }
                                          ]
                                        }
                                      ]
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  ] 

  //Use this return value to inject back into your raw JSON Invoice[0] without Signature/UBLExtension earlier
  //Then, encode back to SHA256 and Base64 respectively for object value inside Submission Document payload.
  return ({
    certificateJsonPortion_Signature,
    certificateJsonPortion_UBLExtensions
  })

} 

async function testIRBCall(data) {
  try {
    const response = await axios.post(`${process.env.PREPROD_BASE_UR}/connect/token`, httpOptions, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    if(response.status == 200) return response.data;
  } catch (err) {
    if (err.response.status == 429) {
      console.log('Current iteration hitting Rate Limit 429 of LHDN Taxpayer Token API, retrying...')
      const rateLimitReset = err.response.headers["x-rate-limit-reset"];

      if (rateLimitReset) {
        const resetTime = new Date(rateLimitReset).getTime();
        const currentTime = Date.now();
        const waitTime = resetTime - currentTime;

        if (waitTime > 0) {
          console.log('=======================================================================================');
          console.log('         (TEST API CALL) LHDN Taxpayer Token API hitting rate limit HTTP 429           ');
          console.log(`              Refetching................. (Waiting time: ${waitTime} ms)               `);
          console.log('=======================================================================================');
          await new Promise(resolve => setTimeout(resolve, waitTime));
          return await getTokenAsTaxPayer();
        }            
      }
    } else {
      throw new Error(`Failed to get token: ${err.message}`);
    }
  }
}

module.exports = { 
    getClientConfig,
    testIRBCall,
    getTokenAsTaxPayer,
    getTokenAsIntermediary,
    submitDocumentAsIntermediary,
    cancelValidDocumentBySupplier,
    getDocumentDetails,
    jsonToBase64,
    calculateSHA256,
    getCertificatesHashedParams
 };
