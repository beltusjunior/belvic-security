// GET /.netlify/functions/reputation?domain=example.com
// Runs the checks a browser can't do on its own (see lib.js).
const { reputation, validDomain } = require("./lib");

exports.handler = async event => {
  const domain = String((event.queryStringParameters || {}).domain || "").trim().toLowerCase();
  const headers = { "content-type": "application/json", "cache-control": "public, max-age=900" };
  if(!validDomain(domain)) return { statusCode: 400, headers, body: JSON.stringify({ error: "invalid domain" }) };
  try{
    return { statusCode: 200, headers, body: JSON.stringify(await reputation(domain)) };
  }catch(e){
    return { statusCode: 502, headers, body: JSON.stringify({ error: "lookup failed" }) };
  }
};
