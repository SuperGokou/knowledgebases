import Image from "next/image";

type BrandIdentityProps = {
  variant?: "sidebar" | "workspace" | "login" | "mobile";
  priority?: boolean;
};

export function BrandIdentity({ variant = "sidebar", priority = false }: BrandIdentityProps) {
  return (
    <span className={`brand-identity ${variant}`} aria-label="江苏和熠光显有限公司企业知识中台">
      <span className="brand-logo-frame" aria-hidden="true">
        <Image
          className="brand-logo-image"
          src="/brand/heyi-display-logo.webp"
          width={544}
          height={544}
          sizes={variant === "login" ? "96px" : variant === "workspace" ? "72px" : variant === "mobile" ? "38px" : "52px"}
          alt=""
          priority={priority}
        />
      </span>
      <span className="brand-wordmark">
        <strong>江苏和熠光显有限公司</strong>
        <small>企业知识中台 · ATLAS</small>
      </span>
    </span>
  );
}
