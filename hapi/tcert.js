"use strict";

var hapi = require("./hapi");

module.exports = {
   tags: ["fabric-ca"],
   description: "Get a batch of transaction certificates with optional attributes.",
   request: {
      method: 'POST',
      path: '/api/v1/cfssl/tcert',
      headers: { Authorization: "$tokenAuthHdr" },
      body: {
        count: "(i)The number of transaction certificates to return.",
	attr_names: ["The name of an attribute whose name and value to put in each transaction certificate."],
	encrypt_attrs: "(b)If true, encrypt the attribute(s) in each transaction certificate.",
	validity_period: "(i)The number of nanoseconds each transaction certificate will be valid before expiration."
      }
   },
   responses: {
      200: {
         description: "Successfully enrolled a new identity",
         body: hapi.getResponseBody({
	    id: "(i)Transaction batch identifier",
	    ts: "(i)Time stamp",
	    key: "Base 64 encoded key",
	    tcerts: [{
	       cert: "Based 64 encoded transaction certificate",
	       keys: [{
                  name: "Attribute name",
                  value: "Base 64 encoded symmetric key"
               }]
            }]
         })
      }
   }
};
