"use strict";

var hapi = require("./hapi");

module.exports = {
   tags: ["fabric-ca"],
   description: "Enroll a new identity and return an enrollment certificate.",
   request: {
      method: 'POST',
      path: '/api/v1/cfssl/enroll',
      headers: { Authorization: "$basicAuthHdr" },
      body: hapi.getEnrollmentRequestBody(false)
   },
   responses: {
      200: {
         description: "Successfully enrolled a new identity",
         body: hapi.getResponseBody("The enrollment certificate in base 64 encoded format.")
      }
   }
};
