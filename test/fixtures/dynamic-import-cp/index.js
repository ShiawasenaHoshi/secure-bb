export async function run() {
  const {exec} = await import("node:child_process");
  exec('id');
}
