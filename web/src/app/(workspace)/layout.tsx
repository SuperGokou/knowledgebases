import { redirect } from "next/navigation";
import { headers } from "next/headers";
import type { ReactNode } from "react";

import { AppShell } from "@/components/app-shell";
import {
  isAuthorizedWorkspaceRequest,
  workspaceEmail,
} from "@/lib/server/workspace-guard";

export const dynamic = "force-dynamic";

export default async function WorkspaceLayout({ children }: { children: ReactNode }) {
  const requestHeaders = await headers();
  if (!isAuthorizedWorkspaceRequest(requestHeaders)) redirect("/login");
  return <AppShell email={workspaceEmail(requestHeaders)}>{children}</AppShell>;
}
