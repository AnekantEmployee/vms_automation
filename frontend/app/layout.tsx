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
    <html lang="en" suppressHydrationWarning>
      <body className={syne.variable} suppressHydrationWarning style={{ margin: 0, padding: 0, background: "#0a0a0f", color: "white", fontFamily: "var(--font-syne), sans-serif", display: "flex", height: "100vh", overflow: "hidden" }}>
        <Sidebar />
        <main style={{ flex: 1, overflowY: "auto", overflowX: "hidden", height: "100vh", background: "#0a0a0f" }}>
          {children}
        </main>
      </body>
    </html>
  );
}
