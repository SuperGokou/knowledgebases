export class RequestBodyTooLargeError extends Error {}

export async function readBoundedBody(
  request: Request,
  maximumBytes: number,
): Promise<ArrayBuffer | undefined> {
  if (["GET", "HEAD"].includes(request.method)) return undefined;

  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 0) {
      throw new RequestBodyTooLargeError("invalid content length");
    }
    if (parsedLength > maximumBytes) {
      throw new RequestBodyTooLargeError("request body exceeds the control-plane limit");
    }
  }

  if (!request.body) return new ArrayBuffer(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel("request body exceeds the control-plane limit");
        throw new RequestBodyTooLargeError("request body exceeds the control-plane limit");
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
