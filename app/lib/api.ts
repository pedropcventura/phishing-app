// lib/api.ts
export async function analyzeUrl(url: string) {
    const res = await fetch(process.env.NEXT_PUBLIC_API_URL!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    if (!res.ok) throw new Error(`Error ${res.status}`)
    return res.json() as Promise<{ url: string; features: Record<string, any> }>
  }
  