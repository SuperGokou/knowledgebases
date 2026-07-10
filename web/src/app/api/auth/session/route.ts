import { NextResponse } from "next/server";

import { sessionView } from "@/lib/server/session";

export async function GET(): Promise<NextResponse> {
  const response = NextResponse.json(await sessionView());
  response.headers.set("Cache-Control", "no-store");
  return response;
}
