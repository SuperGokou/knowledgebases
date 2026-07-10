import { redirect } from "next/navigation";
import type { ReactNode } from "react";

import { AppShell } from "@/components/app-shell";
import { sessionView } from "@/lib/server/session";

export const dynamic = "force-dynamic";

export default async function WorkspaceLayout({ children }: { children: ReactNode }) {
  const session = await sessionView();
  if (!session.authenticated) redirect("/login");
  return <AppShell email={session.email}>{children}</AppShell>;
}
