import { redirect } from "next/navigation";

import { sessionView } from "@/lib/server/session";

export default async function HomePage() {
  const session = await sessionView();
  redirect(session.authenticated ? "/access-pending" : "/login");
}
