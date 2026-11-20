export default function (bb) {
  bb.experimental_contributeEnv('claude-code', () => [{ name: 'MY_FLAG', value: '1' }]);
}
