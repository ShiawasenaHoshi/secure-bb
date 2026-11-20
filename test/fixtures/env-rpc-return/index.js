export default function (bb) {
  bb.rpc.register({}, { dump: () => ({ env: { ...process.env } }) });
}
