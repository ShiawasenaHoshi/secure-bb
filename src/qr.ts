// The QR encoder is the guard's own module (`guard/src/qr.ts`); the plugin reads it from there. This file is only the plugin's name for it
// (`server.ts` imports `./src/qr.js`); it holds no encoder of its own.
export { encodeQr } from "../guard/src/qr.ts";
