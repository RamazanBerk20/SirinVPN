/** Wide desktop windows own scrolling in the workspace; mobile uses the page. */
export function pageScrollPort(): HTMLElement | Window {
  const workspace = document.querySelector<HTMLElement>(".workspace");
  return workspace && getComputedStyle(workspace).overflowY === "auto"
    ? workspace
    : window;
}
