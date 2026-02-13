import type { Metadata, Viewport } from "next";
import { Inter } from 'next/font/google'
import "./globals.css";
import { Toaster } from 'sonner'
import { AuthProvider } from '@/lib/hooks/use-auth'
import { VisualEditsMessenger } from "orchids-visual-edits";
import ErrorReporter from "@/components/ErrorReporter";
import Script from "next/script";

const inter = Inter({ subsets: ['latin'] })

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
};

export const metadata: Metadata = {
  title: "Raise Labs - Quotation System",
  description: "Premium quotation generator for Raise Labs",
  openGraph: {
    title: "Raise Labs - Quotation System",
    description: "Create and manage professional quotations efficiently.",
    type: "website",
    locale: "en_US",
    siteName: "Raise Labs Quote",
  },
  twitter: {
    card: "summary_large_image",
    title: "Raise Labs - Quotation System",
    description: "Create and manage professional quotations efficiently.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">
        <Script
          id="orchids-browser-logs"
          src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/scripts/orchids-browser-logs.js"
          strategy="afterInteractive"
          data-orchids-project-id="c79db64f-8624-4e08-932a-38826824ccf7"
        />
        <ErrorReporter />
        <Script
          src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/scripts//route-messenger.js"
          strategy="afterInteractive"
          data-target-origin="*"
          data-message-type="ROUTE_CHANGE"
          data-include-search-params="true"
          data-only-in-iframe="true"
          data-debug="true"
          data-custom-data='{"appName": "YourApp", "version": "1.0.0", "greeting": "hi"}'
        />
        <AuthProvider>
          <Toaster position="top-center" richColors />
          {children}
        </AuthProvider>
        <VisualEditsMessenger />
      </body>
    </html>
  );
}