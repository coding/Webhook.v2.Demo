const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const verifyWebhook = (req) => {
  if (!req.headers['user-agent'].includes('Coding.net Hook')) {
    return false;
  }
  // Compare their hmac signature to our hmac signature
  // (hmac = hash-based message authentication code)
  const theirSignature = req.headers['x-coding-signature'];
  console.log(theirSignature);
  const payload = JSON.stringify(req.body);
  const secret = process.env.SECRET_TOKEN;
  const ourSignature = `sha1=${crypto.createHmac('sha1', secret).update(payload).digest('hex')}`;
  return crypto.timingSafeEqual(Buffer.from(theirSignature), Buffer.from(ourSignature));
};


const app = express();
app.use(bodyParser.json());

const notAuthorized = (req, res) => {
  console.log('Someone who is NOT Coding is calling, redirect them');
  res.redirect(301, '/'); // Redirect to domain root
};

const authorizationSuccessful = () => {
  console.log('Coding is calling, do something here');
  // TODO: Do something here
};

app.post('*', (req, res) => {
  if (verifyWebhook(req)) {
    // Coding calling
    authorizationSuccessful();
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Thanks Coding <3');
  } else {
    // Someone else calling
    notAuthorized(req, res);
  }
});

app.all('*', notAuthorized); // Only webhook requests allowed at this address

app.listen(3000);

console.log('Webhook service running at http://localhost:3000');

