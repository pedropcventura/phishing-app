// app/layout.tsx
import './globals.css'

export const metadata = {
  title: 'Phishing Detector',
  description: 'Detect phishing URLs in real time',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="pt-BR">
      <body>
        <header className="bg-blue-600 text-white p-4">
          <h1>Phishing Detector</h1>
        </header>
        {children}
      </body>
    </html>
  )
}
