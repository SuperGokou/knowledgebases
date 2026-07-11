type ScrollTarget = {
  scrollIntoView?: (options?: ScrollIntoViewOptions) => unknown;
};

/**
 * Scroll without leaking a patched browser method's return value into a React effect.
 * Some extensions wrap DOM methods and return an object; React would interpret that
 * value as an effect cleanup callback if the call were returned implicitly.
 */
export function scrollIntoViewIfSupported(
  target: ScrollTarget | null,
  options?: ScrollIntoViewOptions,
): void {
  if (typeof target?.scrollIntoView === "function") {
    target.scrollIntoView(options);
  }
}
