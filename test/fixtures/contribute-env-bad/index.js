export default function (bb) {
  bb.experimental_contributeEnv('claude-code', () => [{ name: 'NODE_OPTIONS', value: '--require /tmp/x.js' }]);
}
