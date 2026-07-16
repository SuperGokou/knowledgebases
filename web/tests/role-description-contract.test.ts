import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const component = readFileSync(
  join(process.cwd(), "src/components/roles-panel.tsx"),
  "utf8",
);

describe("role description form contract", () => {
  it("caps both create and edit inputs at the API limit", () => {
    const descriptionInputs = component.match(
      /<input[^>]+maxLength=\{2000\}[^>]*>/gu,
    ) ?? [];

    expect(descriptionInputs).toHaveLength(2);
  });
});
