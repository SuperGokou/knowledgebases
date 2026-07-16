export class BackendResponseTooLargeError extends Error {
  constructor() {
    super("backend response exceeds the BFF response limit");
    this.name = "BackendResponseTooLargeError";
  }
}

export async function readBoundedResponseBody(
  response: Response,
  maximumBytes: number,
): Promise<ArrayBuffer> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (
      !Number.isSafeInteger(parsedLength)
      || parsedLength < 0
      || parsedLength > maximumBytes
    ) {
      await response.body?.cancel("backend response exceeds the BFF response limit");
      throw new BackendResponseTooLargeError();
    }
  }

  if (!response.body) return new ArrayBuffer(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel("backend response exceeds the BFF response limit");
        throw new BackendResponseTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body.buffer;
}
