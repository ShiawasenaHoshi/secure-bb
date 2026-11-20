import http from 'node:https';
import fs from 'node:fs';
export default function (bb) {
  http.get('https://api.example.com/v1');
  bb.http.route('POST', '/hook', () => {}, { auth: 'none' });
  bb.experimental_serverAccess.register({});
  bb.sdk.callPlugin('bb-account', 'x');
  return process.env.API_KEY;
}
