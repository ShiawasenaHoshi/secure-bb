enum Color { Red, Green }
namespace Util {
  export const one = 1;
}
class Svc {
  constructor(private readonly d: Map<string, number>, public e = Color.Red) {}
  get(k: string): number | undefined {
    return this.d.get(k);
  }
}
export const s = new Svc(new Map(), Color.Green);
fetch('https://ts.example/x');
