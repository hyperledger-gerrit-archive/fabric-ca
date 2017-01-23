"use strict";

var hapi = require("./hapi");

module.exports = {
   tags: ["fabric-ca"],
   description: "Perform revocation of one of the following: \n"+
                "* a specific certificate identified by a serial number and AKI (Authority Key Identitifer), or  \n"+
                "* all certificates associated with the identity and prevent any future enrollments for this identity.  \n"+
                "The caller must have the **hf.Revoker** attribute.",
   request: {
      method: 'POST',
      path: '/api/v1/cfssl/revoke',
      headers: { Authorization: "$tokenAuthHdr" },
      body: {
         to_revoke: [{
            id: "(opt)The enrollment ID of the identity whose certificates are to be revoked,  \n"+
                "including both enrollment certificates and transaction certificates.   \n"+
                "All future enrollment attempts for this identity will be rejected.  \n"+
                "If this field is specified, the *serial* and *aki* fields are ignored.",
            cert: {
               aki: "The Authority Key Identifier of the certificate which is to be revoked.  \n"+
                    "The *serial* field must also be specified.",
               serial: "The serial number of the certificate which is to be revoked.  \n"+
                       "The *aki* (Authority Key Identifier) field must also be specified."
            },
            reason: "(opt)The reason for revocation.  \n"+
                    "See https://godoc.org/golang.org/x/crypto/ocsp for valid values.  \n"+
                    "The default value is 0 (ocsp.Unspecified)."
        }]
      }
   },
   responses: {
      200: {
         description: "Successfully completed the revocation",
         body: hapi.getResponseBody({revoked:[{
            aki:"The Authority Key Identifier of a revoked certificate",
            serial:"The serial number of a revoked certificate"}]}),
         bodymd: {
            Result: {
               description: "An array of AKI (Authority Key Identifier) and serial number tuples, each identifying a certificate which was revoked by this operation."
            }
         }
      }
   }
};
