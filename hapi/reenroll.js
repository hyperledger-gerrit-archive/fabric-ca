"use strict";

var hapi = require("./hapi");

module.exports = {
   tags: ["fabric-ca"],
   description: "Reenroll an enrollment certificate.  "+
                "This is useful for renewing an enrollment certificate before it expires or because it has been compromised.\n",
   request: {
      method: 'POST',
      path: '/api/v1/cfssl/reenroll',
      headers: { Authorization: "$tokenAuthHdr" },
      body: hapi.getEnrollmentRequestBody(true)
   },
   responses: {
      200: {
         description: "Successfully registered identity",
         body: hapi.getResponseBody("The enrollment certificate in base 64 encoded format.")
      }
   }
};
