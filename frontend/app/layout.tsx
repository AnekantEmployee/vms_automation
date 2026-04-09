import type { Metadata } from "next";
import { Syne } from "next/font/google";
import "./globals.css";
import Sidebar from "@/components/Sidebar";

const syne = Syne({
  subsets: ["latin"],
  variable: "--font-syne",
  weight: ["400", "500", "600", "700", "800"],
});

export const metadata: Metadata = {
  title: "VMS",
  description: "Vulnerability Management System",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning style={{ height: "100%" }}>
      <body
        className={syne.variable}
        suppressHydrationWarning
        style={{
          height: "100%",
          display: "flex",
          background: "#0a0a0f",
          color: "white",
          fontFamily: "var(--font-syne), sans-serif",
        }}
      >
        {/* Sidebar — fixed width, full height */}
        <aside style={{
          width: "240px",
          minWidth: "240px",
          height: "100vh",
          position: "sticky",
          top: 0,
          background: "#0d0d14",
          borderRight: "1px solid #1f1f2e",
          display: "flex",
          flexDirection: "column",
          flexShrink: 0,
        }}>
          <Sidebar />
        </aside>

        {/* Main content — scrollable */}
        <main style={{
          flex: 1,
          height: "100vh",
          overflowY: "auto",
          background: "#0a0a0f",
        }}>
          {children}
        </main>
      </body>
    </html>
  );
}
