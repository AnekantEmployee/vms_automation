"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  {
    label: "Asset Scanning",
    href: "/asset-scanning",
    icon: (
      <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8}
          d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />
      </svg>
    ),
  },
  {
    label: "CVE Exploitability",
    href: "/cve-exploitability",
    icon: (
      <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8}
          d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      </svg>
    ),
  },
];

export default function Sidebar() {
  const path = usePathname();

  return (
    <aside style={{
      width: "220px",
      minWidth: "220px",
      height: "100vh",
      background: "#0d0d14",
      borderRight: "1px solid #1f1f2e",
      display: "flex",
      flexDirection: "column",
      flexShrink: 0,
      overflow: "hidden",
    }}>
      {/* Logo */}
      <div style={{ padding: "22px 20px 18px", borderBottom: "1px solid #1f1f2e", flexShrink: 0 }}>
        <div style={{ fontSize: "20px", fontWeight: 800, color: "white", letterSpacing: "-0.5px", whiteSpace: "nowrap" }}>
          V<span style={{ color: "#00ff9d" }}>MS</span>
        </div>
        <div style={{ fontSize: "11px", color: "#52525b", marginTop: "3px", whiteSpace: "nowrap" }}>
          Vulnerability Management
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "10px 8px", overflowY: "auto" }}>
        {NAV.map((item) => {
          const active = path.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                padding: "10px 12px",
                borderRadius: "8px",
                fontSize: "13px",
                fontWeight: 500,
                textDecoration: "none",
                color: active ? "#00ff9d" : "#a1a1aa",
                background: active ? "rgba(0,255,157,0.07)" : "transparent",
                border: active ? "1px solid rgba(0,255,157,0.15)" : "1px solid transparent",
                transition: "all 0.15s",
                whiteSpace: "nowrap",
                overflow: "hidden",
              }}
            >
              <span style={{ flexShrink: 0 }}>{item.icon}</span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div style={{ padding: "14px 20px", borderTop: "1px solid #1f1f2e", flexShrink: 0 }}>
        <span style={{ fontSize: "11px", color: "#3f3f46", whiteSpace: "nowrap" }}>VMS v1.0</span>
      </div>
    </aside>
  );
}
