import "./globals.css";
import Link from "next/link";

export const metadata = { title: "Rathnone Console" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="bar">
            <h1>RATHNONE</h1>
            <span className="tag">Sovereign Finance Gateway · local-first authority</span>
          </header>
          <nav className="tabs">
            <Link href="/">Tenants</Link>
            <Link href="/authorize">Authorize</Link>
            <Link href="/audit">Audit &amp; Meter</Link>
            <Link href="/trace">Trace</Link>
          </nav>
          {children}
        </div>
      </body>
    </html>
  );
}
