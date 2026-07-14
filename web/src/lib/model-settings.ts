export type ProviderUpdateInput = {
  model: string;
  baseUrl: string;
  apiKey: string;
  inputPriceUsd: string;
  outputPriceUsd: string;
};

export type ProviderUpdatePayload = {
  model: string;
  base_url: string;
  make_default: true;
  api_key?: string;
  input_micro_usd_per_million_tokens?: number;
  output_micro_usd_per_million_tokens?: number;
};

const USD_PRICE_PATTERN = /^(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,6})?$/u;

export function usdToMicroUsd(value: string): number {
  const normalized = value.trim();
  if (normalized.startsWith("-")) throw new Error("价格不能为负数");
  if (!USD_PRICE_PATTERN.test(normalized)) {
    throw new Error("价格必须是非负数，且最多保留 6 位小数");
  }
  const [whole, fraction = ""] = normalized.split(".");
  const microUsd = Number(whole) * 1_000_000 + Number(fraction.padEnd(6, "0"));
  if (!Number.isSafeInteger(microUsd) || microUsd > 10 ** 15) {
    throw new Error("价格超出系统允许范围");
  }
  return microUsd;
}

export function microUsdToUsd(value: number | null): string {
  if (value === null) return "";
  const whole = Math.floor(value / 1_000_000);
  const fraction = String(value % 1_000_000).padStart(6, "0").replace(/0+$/u, "");
  return fraction ? `${whole}.${fraction}` : String(whole);
}

export function buildProviderUpdate(input: ProviderUpdateInput): ProviderUpdatePayload {
  const inputPrice = input.inputPriceUsd.trim();
  const outputPrice = input.outputPriceUsd.trim();
  if (Boolean(inputPrice) !== Boolean(outputPrice)) {
    throw new Error("输入与输出价格必须同时填写");
  }
  const payload: ProviderUpdatePayload = {
    model: input.model.trim(),
    base_url: input.baseUrl.trim(),
    make_default: true,
  };
  if (input.apiKey.trim()) payload.api_key = input.apiKey.trim();
  if (inputPrice && outputPrice) {
    payload.input_micro_usd_per_million_tokens = usdToMicroUsd(inputPrice);
    payload.output_micro_usd_per_million_tokens = usdToMicroUsd(outputPrice);
  }
  return payload;
}
