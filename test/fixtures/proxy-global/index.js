const g = new Proxy(globalThis, {});
export default g.eval('1');
