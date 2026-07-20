import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { buildProviderUpdate, microUsdToUsd, usdToMicroUsd } from "../src/lib/model-settings";

const modelSettingsPanel = readFileSync(
  join(process.cwd(), "src/components/model-settings-panel.tsx"),
  "utf8",
);

describe("model provider pricing settings", () => {
  it("never reports a configured default as running while runtime egress is disabled", () => {
    expect(modelSettingsPanel).toContain(
      'if (!runtimeEnabled) return { label: "模型外呼未开启", tone: "warning" };',
    );
    expect(modelSettingsPanel).toContain(
      'if (!defaultConfigured) return { label: "外呼已开启 · 待配置", tone: "warning" };',
    );
    expect(modelSettingsPanel).toContain(
      'return { label: "模型外呼已开启", tone: "info" };',
    );
    expect(modelSettingsPanel).not.toContain("正在运行");
    expect(modelSettingsPanel).toContain("当前部署未开启模型外呼");
    expect(modelSettingsPanel).toContain("新请求仍使用本地检索");
  });

  it("converts an operator-friendly USD price without floating point drift", () => {
    expect(usdToMicroUsd("0.80")).toBe(800_000);
    expect(usdToMicroUsd("2")).toBe(2_000_000);
    expect(microUsdToUsd(800_000)).toBe("0.8");
    expect(microUsdToUsd(null)).toBe("");
  });

  it("rejects incomplete or invalid price pairs", () => {
    expect(() => usdToMicroUsd("-1")).toThrow("价格不能为负数");
    expect(() => buildProviderUpdate({
      model: "qwen-plus",
      baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
      apiKey: "",
      inputPriceUsd: "0.8",
      outputPriceUsd: "",
    })).toThrow("输入与输出价格必须同时填写");
  });

  it("builds the API payload using integer micro-dollars per million tokens", () => {
    expect(buildProviderUpdate({
      model: "qwen-plus",
      baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
      apiKey: "secret-key",
      inputPriceUsd: "0.8",
      outputPriceUsd: "2",
    })).toEqual({
      model: "qwen-plus",
      base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
      make_default: true,
      api_key: "secret-key",
      input_micro_usd_per_million_tokens: 800_000,
      output_micro_usd_per_million_tokens: 2_000_000,
    });
  });
});
