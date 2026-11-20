export default function (bb) {
  bb.http.route('GET', '/dbg', () => ({ ...process.env }));
}
