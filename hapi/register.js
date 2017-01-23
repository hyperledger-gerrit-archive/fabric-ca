"use strict";

module.exports = {
   tags: ["fabric-ca"],
   description: "Register a new identity with the Fabric CA.  \n"+
                "An enrollment secret is returned which can then be used, along with the enrollment ID, "+
                "to enroll a new identity.  \n"+
                "The caller must have **hf.Registrar** authority.",
   request: {
      method: 'POST',
      path: '/api/v1/cfssl/register',
      headers: { Authorization: "$tokenAuthHdr" },
      body: {
         id: "The enrollment ID which uniquely identifies an identity",
         type: "The type of the identity (e.g. *user*, *app*, *peer*, *orderer*, etc)",
         secret: "(opt)The enrollment secret.  If not provided, a random secret is generated.",
         max_enrollments: "(i,opt)The maximum number of times that the secret can be used to enroll.  \n"+
                          "If 0, use the configured max_enrollments of the fabric-ca server;  \n"+
                          "If > 0 and <= configured max enrollments of the fabric-ca server, use max_enrollments;  \n"+
                          "If > configured max enrollments of the fabric-ca server, error.",
         affiliation_path: "The affiliation path of the new identity.\n",
         attrs: [ { name: "Attribute name", value: "Value of attribute" } ]
      }
   },
   responses: {
      201: {
         description: "Successfully registered identity",
         body: {
            secret: "$enrollmentSecret"
         }
      }
   }
};
