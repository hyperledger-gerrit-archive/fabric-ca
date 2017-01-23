This directory contains javascript files which were used to generate the
swagger/swagger-fabric-ca.json file.  The tool which generated the
swagger file is an npm module called "hapi-doc-test".
See https://www.npmjs.com/package/hapi-doc-test.

To install hapi-doc-test:
   npm install hapi-doc-test

To generate the swagger-fabric-ca.json file, run:
   make swagger

Notes:
* I haven't yet seen how to add an endpoint to fabric-ca to display the swagger doc.
  The go-swagger package seems to only generate code but not seeing how to plug in
  to existing code.
* I tried to convert the json to html using swagger-codegen, but it doesn't
  convert well at all.
* I investigated using annotations but didn't have any success.
