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
];

export default function Sidebar() {
  const path = usePathname();

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Logo */}
      <div style={{ padding: "24px 20px", borderBottom: "1px solid #1f1f2e" }}>
        <div style={{ fontSize: "20px", fontWeight: 800, color: "white", letterSpacing: "-0.5px" }}>
          V<span style={{ color: "#00ff9d" }}>MS</span>
        </div>
        <div style={{ fontSize: "11px", color: "#52525b", marginTop: "2px" }}>
          Vulnerability Management
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "12px 10px" }}>
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
              }}
            >
              {item.icon}
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div style={{ padding: "16px 20px", borderTop: "1px solid #1f1f2e" }}>
        <span style={{ fontSize: "11px", color: "#3f3f46" }}>VMS v1.0</span>
      </div>
    </div>
  );
}
