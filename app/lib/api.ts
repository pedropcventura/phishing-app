// lib/api.ts
export async function analyzeUrl(url: string) {
    const res = await fetch("http://localhost:10000/api/analyze", {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    if (!res.ok) throw new Error(`Error ${res.status}`)
    return res.json() as Promise<{ url: string; features: Record<string, any> }>
  }
  