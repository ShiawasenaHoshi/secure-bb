const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
export default new AsyncFunction('return 1');
