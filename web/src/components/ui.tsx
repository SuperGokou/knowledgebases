import type { ReactNode } from "react";

import { Icon, type IconName } from "@/components/icon";

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action ? <div className="page-header-action">{action}</div> : null}
    </header>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  compact = false,
}: {
  icon: IconName;
  title: string;
  description: string;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={`empty-state${compact ? " compact" : ""}`}>
      <span className="empty-icon"><Icon name={icon} /></span>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  retryLabel = "重试",
  title = "暂时无法加载",
}: {
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
  title?: string;
}) {
  return (
    <div className="notice error-notice" role="alert">
      <Icon name="warning" />
      <div>
        <strong>{title}</strong>
        <p>{message}</p>
      </div>
      {onRetry ? (
        <button className="button ghost small" type="button" onClick={onRetry}>
          <Icon name="refresh" /> {retryLabel}
        </button>
      ) : null}
    </div>
  );
}

export function LoadingRows({ count = 4 }: { count?: number }) {
  return (
    <div className="loading-rows" aria-label="正在加载">
      {Array.from({ length: count }, (_, index) => (
        <div className="loading-row" key={index}>
          <span className="skeleton square" />
          <span className="skeleton wide" />
          <span className="skeleton short" />
        </div>
      ))}
    </div>
  );
}

export function StatusBadge({ tone, children }: { tone: "success" | "warning" | "danger" | "neutral" | "info"; children: ReactNode }) {
  return <span className={`status-badge ${tone}`}>{children}</span>;
}

export function StatCard({
  label,
  value,
  detail,
  icon,
  tone = "blue",
}: {
  label: string;
  value: string;
  detail: string;
  icon: IconName;
  tone?: "blue" | "violet" | "green" | "amber";
}) {
  return (
    <article className="stat-card">
      <span className={`stat-icon ${tone}`}><Icon name={icon} /></span>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </article>
  );
}
