"use client"

import type React from "react"

import { useState } from "react"
import { analyzeUrl } from "./lib/api"
import { Shield, AlertTriangle, CheckCircle, Loader2, AlertCircle, Info } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

type ApiResponse = {
  features: {
    bad_ip: number
    country: string
    digit_substitution: number
    domain_age_days: number
    dynamic_dns: number
    excessive_subdomains: number
    explanation: {
      negative_factors: string[]
      positive_factors: string[]
    }
    hf_confidence: number
    hf_phishing: number
    login_form: number
    min_levenshtein: number
    oauth_suspicious: number
    phish_in_database: number
    phish_valid: number
    redirect_suspicious: number
    risk_level: string
    risk_score: number
    special_characters: number
    ssl_valid_days: number
    url_length: number
  }
  url: string
}

export default function PhishingAnalyzer() {
  const [url, setUrl] = useState("")
  const [results, setResults] = useState<ApiResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // Basic URL validation
    if (!url.trim() || !url.match(/^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w- ./?%&=]*)?$/)) {
      setError("Please enter a valid URL")
      return
    }

    setLoading(true)
    setError("")

    try {
      const cleanUrl = url.replace(/^https?:\/\//, "")
      const analysisResults = await analyzeUrl(cleanUrl)
      setResults(analysisResults as ApiResponse)
    } catch (err) {
      setError("Failed to analyze URL. Please try again.")
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const getRiskBadge = (riskLevel: string) => {
    switch (riskLevel) {
      case "Very Low":
        return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">Very Safe</Badge>
      case "Low":
        return <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300">Safe</Badge>
      case "Medium":
        return (
          <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300">Suspicious</Badge>
        )
      case "High":
        return (
          <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300">High Risk</Badge>
        )
      case "Very High":
        return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300">Dangerous</Badge>
      default:
        return <Badge variant="outline">{riskLevel}</Badge>
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return "bg-green-500"
    if (score >= 75) return "bg-blue-500"
    if (score >= 50) return "bg-yellow-500"
    if (score >= 30) return "bg-orange-500"
    return "bg-red-500"
  }

  return (
    <main className="container mx-auto px-4 py-10 max-w-4xl">
      <div className="flex flex-col items-center text-center mb-8">
        <Shield className="h-12 w-12 mb-4 text-primary" />
        <h1 className="text-3xl font-bold tracking-tight mb-2">Phishing URL Analyzer</h1>
        <p className="text-muted-foreground max-w-md">Enter a URL to analyze and detect potential phishing threats</p>
      </div>

      <Card className="mb-8">
        <CardHeader>
          <CardTitle>Analyze URL</CardTitle>
          <CardDescription>Enter the URL you want to check for phishing indicators</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
            <Input
              type="text"
              placeholder="facebook.com or google.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1"
            />
            <Button type="submit" disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Analyzing
                </>
              ) : (
                "Analyze"
              )}
            </Button>
          </form>

          {error && (
            <Alert variant="destructive" className="mt-4">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              Analysis Results
              {getRiskBadge(results.features.risk_level)}
            </CardTitle>
            <CardDescription>
              Analysis for: <span className="font-medium">{results.url}</span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="summary" className="mt-2">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="summary">Summary</TabsTrigger>
                <TabsTrigger value="details">Details</TabsTrigger>
                <TabsTrigger value="factors">Risk Factors</TabsTrigger>
              </TabsList>

              <TabsContent value="summary" className="space-y-6 pt-4">
                <div>
                  <h3 className="text-lg font-medium mb-2">Risk Score</h3>
                  <div className="flex items-center gap-4">
                    <div className="w-full flex-1">
                      <Progress value={results.features.risk_score} className="h-4">
                        <div
                          className={`h-full ${getScoreColor(results.features.risk_score)}`}
                          style={{ width: `${results.features.risk_score}%` }}
                        ></div>
                      </Progress>
                    </div>
                    <span className="text-xl font-semibold whitespace-nowrap">{results.features.risk_score}/100</span>
                  </div>
                  <p className="mt-2 text-sm text-muted-foreground">
                    Higher score means the URL is more likely to be legitimate.
                  </p>
                </div>

                <Separator />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="text-lg font-medium mb-3">Negative Factors</h3>
                    {results.features.explanation.negative_factors.length > 0 ? (
                      <ul className="space-y-2">
                        {results.features.explanation.negative_factors.map((factor, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <AlertCircle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                            <span>{factor}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-muted-foreground">No negative factors detected.</p>
                    )}
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-3">Positive Factors</h3>
                    {results.features.explanation.positive_factors.length > 0 ? (
                      <ul className="space-y-2">
                        {results.features.explanation.positive_factors.map((factor, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 shrink-0" />
                            <span>{factor}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-muted-foreground">No positive factors detected.</p>
                    )}
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="details" className="pt-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                  <Card>
                    <CardHeader className="py-3">
                      <CardTitle className="text-sm font-medium">Domain Age</CardTitle>
                    </CardHeader>
                    <CardContent className="py-2">
                      <p className="text-2xl font-semibold">{results.features.domain_age_days} days</p>
                      <p className="text-xs text-muted-foreground">
                        {results.features.domain_age_days > 365 ? "Established domain" : "Recently registered"}
                      </p>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="py-3">
                      <CardTitle className="text-sm font-medium">SSL Certificate</CardTitle>
                    </CardHeader>
                    <CardContent className="py-2">
                      <p className="text-2xl font-semibold">{results.features.ssl_valid_days} days</p>
                      <p className="text-xs text-muted-foreground">
                        {results.features.ssl_valid_days > 0 ? "Valid certificate" : "Invalid or missing"}
                      </p>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="py-3">
                      <CardTitle className="text-sm font-medium">ML Confidence</CardTitle>
                    </CardHeader>
                    <CardContent className="py-2">
                      <p className="text-2xl font-semibold">{(results.features.hf_confidence * 100).toFixed(2)}%</p>
                      <p className="text-xs text-muted-foreground">
                        {results.features.hf_phishing === 0 ? "Legitimate URL" : "Potential phishing"}
                      </p>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="py-3">
                      <CardTitle className="text-sm font-medium">URL Properties</CardTitle>
                    </CardHeader>
                    <CardContent className="py-2">
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>Length:</div>
                        <div className="font-medium">{results.features.url_length} chars</div>

                        <div>Special Chars:</div>
                        <div className="font-medium">{results.features.special_characters ? "Yes" : "No"}</div>

                        <div>Digit Subst.:</div>
                        <div className="font-medium">{results.features.digit_substitution ? "Yes" : "No"}</div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="py-3">
                      <CardTitle className="text-sm font-medium">Suspicious Patterns</CardTitle>
                    </CardHeader>
                    <CardContent className="py-2">
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>Redirects:</div>
                        <div className="font-medium">
                          {results.features.redirect_suspicious ? "Suspicious" : "Normal"}
                        </div>

                        <div>Login Form:</div>
                        <div className="font-medium">{results.features.login_form ? "Present" : "None"}</div>

                        <div>OAuth:</div>
                        <div className="font-medium">{results.features.oauth_suspicious ? "Suspicious" : "Normal"}</div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="py-3">
                      <CardTitle className="text-sm font-medium">Known Risks</CardTitle>
                    </CardHeader>
                    <CardContent className="py-2">
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>In Database:</div>
                        <div className="font-medium">{results.features.phish_in_database ? "Yes" : "No"}</div>

                        <div>Bad IP:</div>
                        <div className="font-medium">{results.features.bad_ip ? "Yes" : "No"}</div>

                        <div>Country:</div>
                        <div className="font-medium">{results.features.country}</div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              <TabsContent value="factors" className="pt-4">
                <Alert className="mb-6">
                  <Info className="h-4 w-4" />
                  <AlertTitle>Risk Assessment</AlertTitle>
                  <AlertDescription>
                    This analysis combines machine learning models with rules-based detection to identify phishing
                    attempts.
                  </AlertDescription>
                </Alert>

                <div className="space-y-4">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Key Risk Indicators</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="flex items-center p-3 rounded-md bg-secondary/50">
                        <div
                          className={`w-3 h-3 rounded-full ${results.features.domain_age_days < 30 ? "bg-red-500" : "bg-green-500"} mr-3`}
                        ></div>
                        <div>
                          <p className="font-medium">Domain Age</p>
                          <p className="text-sm text-muted-foreground">
                            Phishing sites often use newly registered domains
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center p-3 rounded-md bg-secondary/50">
                        <div
                          className={`w-3 h-3 rounded-full ${results.features.ssl_valid_days === 0 ? "bg-red-500" : "bg-green-500"} mr-3`}
                        ></div>
                        <div>
                          <p className="font-medium">SSL Certificate</p>
                          <p className="text-sm text-muted-foreground">
                            Legitimate sites typically have valid SSL certificates
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center p-3 rounded-md bg-secondary/50">
                        <div
                          className={`w-3 h-3 rounded-full ${results.features.login_form && results.features.domain_age_days < 180 ? "bg-red-500" : "bg-green-500"} mr-3`}
                        ></div>
                        <div>
                          <p className="font-medium">Login Form</p>
                          <p className="text-sm text-muted-foreground">
                            Login forms on new domains are common in phishing
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center p-3 rounded-md bg-secondary/50">
                        <div
                          className={`w-3 h-3 rounded-full ${results.features.redirect_suspicious ? "bg-red-500" : "bg-green-500"} mr-3`}
                        ></div>
                        <div>
                          <p className="font-medium">Redirections</p>
                          <p className="text-sm text-muted-foreground">
                            Suspicious redirects may indicate phishing attempts
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center p-3 rounded-md bg-secondary/50">
                        <div
                          className={`w-3 h-3 rounded-full ${results.features.phish_in_database ? "bg-red-500" : "bg-green-500"} mr-3`}
                        ></div>
                        <div>
                          <p className="font-medium">Known Phishing</p>
                          <p className="text-sm text-muted-foreground">URL has been previously reported as phishing</p>
                        </div>
                      </div>

                      <div className="flex items-center p-3 rounded-md bg-secondary/50">
                        <div
                          className={`w-3 h-3 rounded-full ${results.features.hf_phishing ? "bg-red-500" : "bg-green-500"} mr-3`}
                        ></div>
                        <div>
                          <p className="font-medium">ML Detection</p>
                          <p className="text-sm text-muted-foreground">Machine learning model classification result</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Safety Recommendations</h3>
                    <ul className="list-disc pl-5 space-y-1">
                      <li className="text-muted-foreground">
                        Always verify the domain name before entering credentials
                      </li>
                      <li className="text-muted-foreground">Check for HTTPS and a valid SSL certificate</li>
                      <li className="text-muted-foreground">Be cautious of URLs sent via email or messages</li>
                      <li className="text-muted-foreground">
                        When in doubt, go directly to the service's website by typing the URL
                      </li>
                      <li className="text-muted-foreground">
                        Use a password manager that will only fill credentials on legitimate sites
                      </li>
                    </ul>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </main>
  )
}
