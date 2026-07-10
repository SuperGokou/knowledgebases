import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "江苏和熠光显有限公司 · 企业知识中台", template: "%s · 和熠光显" },
  description: "江苏和熠光显有限公司面向企业文档、权限与智能问答的安全知识工作台",
  applicationName: "和熠光显企业知识中台",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
