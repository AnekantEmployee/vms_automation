import type { Metadata } from "next";
import { Syne } from "next/font/google";
import "./globals.css";
import WSListener from "@/components/WSListener";

const syne = Syne({
  subsets: ["latin"],
  variable: "--font-syne",
  weight: ["400", "500", "600", "700", "800"],
});

export const metadata: Metadata = {
  title: "ExcelFlow",
  description: "Process Excel files row by row, live",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${syne.variable} antialiased`} suppressHydrationWarning>
        <WSListener />
        {children}
      </body>
    </html>
  );
}
