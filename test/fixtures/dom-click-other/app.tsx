export default function X() {
  document.querySelector(".some-panel > .toggle")?.dispatchEvent(new MouseEvent("click"));
  return null;
}
