"use strict";

module.exports = {

   hapi: {
      virtual_host: {
         name: "fabric-ca",
         host_variable: "url",
         swagger: {
            swagger: "2.0",
            info: {
               version: "0.7.0",
               title: "Fabric CA API",
               description: "Hyperledger Fabric CA APIs provides certificate authority services for the blockchain."
            },
            schemes: ["https", "http"],
            consumes: ["application/json"],
            produces: ["application/json"],
            tags: [{
               name: "fabric-ca",
               description: "Fabric CA related APIs"
            }]
         }
      },
      variables: {
         enrollmentID: {
            description: "enrollment ID"
         },
         enrollmentSecret: {
            description: "enrollment secret"
         },
         basicAuthHdr: {
            description: "An HTTP basic authorization header where:  \n"+
                         "*   *user* is the enrollment ID;  \n"+
                         "*  *password* is the enrollment secret.",
            value: { base64Encode: "$enrollmentID:$enrollmentSecret" }
         },
         tokenAuthHdr: {
            description: "An enrollment token consisting of two base 64 encoded parts separated by a period:  \n"+
                         "* an enrollment certificate;  \n"+
                         "* a signature over the certificate and body of request."
         },
         foo: {
            description: "(sa,opt)An optional array of strings.",
            value: "$enrollmentID"
         }
      }
   },

   getEnrollmentRequestBody: function(isReenroll) {
      var b = {};
      if (!isReenroll) {
         b.id = "The enrollment ID";
         b.secret = "The enrollment secret which was returned from the register call";
      }
      b.hosts = "(opt)A comma-separated list of host names to associate with the certificate.";
      b.profile = "(opt)The name of the signing profile to use when issuing the certificate.";
      b.label = "(opt)The label used in HSM operations";
      b.csr = {
         CN: "The common name",
         names: [{
            C: "(opt)The country name",
            ST: "(opt)The state name",
            L: "(opt)The locality name",
            O: "(opt)The organization name",
            OU: "(opt)The organization name",
            SerialNumber: "(opt)The requested serial number",
         }],
         hosts: ["A host name"],
         key: {
            algo: "The key algorithm name",
            size: "The key size in bytes"
         },
         serial_number: "(opt)An optional requested serial number"
      };
      return b;
   },

   getResponseBody: function (result) {
      return {
         Success: "(b)Boolean indicating if the request was successful.",
         Result: result,
         Errors: [{
            code: "(i)Integer code denoting the type of error.",
            message: "An error message"
         }],
         Messages: [{
            code: "(i)Integer code denoting the type of message.",
            message: "A more specific message."
         }]
      };
   }

};
