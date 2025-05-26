"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { analyzeUrl } from "./lib/api"
import { Shield, AlertTriangle, Loader2, Clock, X, Database, Globe, Lock, Eye, Activity, Zap } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
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

type HistoryItem = {
  url: string
  timestamp: number
  riskLevel: string
  riskScore: number
}

export default function PhishingAnalyzer() {
  const [url, setUrl] = useState("")
  const [results, setResults] = useState<ApiResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [searchHistory, setSearchHistory] = useState<HistoryItem[]>([])
  const [showHistory, setShowHistory] = useState(false)

  // Load search history from localStorage on component mount
  useEffect(() => {
    const savedHistory = localStorage.getItem("phishing-analyzer-history")
    if (savedHistory) {
      try {
        setSearchHistory(JSON.parse(savedHistory))
      } catch (e) {
        console.error("Failed to parse search history", e)
      }
    }
  }, [])

  // Save search history to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem("phishing-analyzer-history", JSON.stringify(searchHistory))
  }, [searchHistory])

  const addToHistory = (analysisResults: ApiResponse) => {
    const cleanUrl = analysisResults.url.replace(/^https?:\/\//, "").replace(/\/$/, "")

    // Create history item
    const historyItem: HistoryItem = {
      url: cleanUrl,
      timestamp: Date.now(),
      riskLevel: analysisResults.features.risk_level,
      riskScore: analysisResults.features.risk_score,
    }

    // Add to history, avoiding duplicates (replace if exists)
    setSearchHistory((prev) => {
      const filtered = prev.filter((item) => item.url !== cleanUrl)
      return [historyItem, ...filtered].slice(0, 10) // Keep only the 10 most recent
    })
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    await analyzeUrlAndUpdateUI(url)
  }

  const analyzeUrlAndUpdateUI = async (urlToAnalyze: string) => {
    // Basic URL validation
    if (!urlToAnalyze.trim() || !urlToAnalyze.match(/^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w- ./?%&=]*)?$/)) {
      setError("Please enter a valid URL")
      return
    }

    setLoading(true)
    setError("")
    setUrl(urlToAnalyze) // Update the input field

    try {
      const analysisResults = await analyzeUrl(urlToAnalyze)
      setResults(analysisResults as ApiResponse)
      addToHistory(analysisResults as ApiResponse)
    } catch (err) {
      setError("Failed to analyze URL. Please try again.")
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const clearHistory = () => {
    setSearchHistory([])
    localStorage.removeItem("phishing-analyzer-history")
  }

  const removeHistoryItem = (urlToRemove: string, e: React.MouseEvent) => {
    e.stopPropagation() // Prevent triggering the parent click handler
    setSearchHistory((prev) => prev.filter((item) => item.url !== urlToRemove))
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

  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleString()
  }

  const getBooleanBadge = (value: number, trueText: string, falseText: string) => {
    return value === 1 ? (
      <Badge variant="destructive">{trueText}</Badge>
    ) : (
      <Badge variant="secondary">{falseText}</Badge>
    )
  }

  const getFeatureCard = (title: string, value: string | number, description: string, icon: React.ReactNode) => (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <p className="text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  )

  return (
    <main className="container mx-auto px-4 py-10 max-w-6xl">
      <div className="flex flex-col items-center text-center mb-8">
        <Shield className="h-12 w-12 mb-4 text-primary" />
        <h1 className="text-3xl font-bold tracking-tight mb-2">Phishing URL Analyzer</h1>
        <p className="text-muted-foreground max-w-md">Enter a URL to analyze and detect potential phishing threats</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Analyze URL</CardTitle>
            <CardDescription>Enter the URL you want to check for phishing indicators</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
              <Input
                type="text"
                placeholder="insper.edu.br or facebook.com"
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

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Search History</CardTitle>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={() => setShowHistory(!showHistory)}>
              <Clock className="h-4 w-4" />
              <span className="sr-only">Toggle history</span>
            </Button>
          </CardHeader>
          <CardContent>
            {searchHistory.length === 0 ? (
              <p className="text-sm text-muted-foreground">No search history yet</p>
            ) : (
              <>
                <p className="text-sm text-muted-foreground mb-3">
                  {showHistory ? `${searchHistory.length} recent searches` : "Click to show history"}
                </p>

                {showHistory && (
                  <>
                    <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                      {searchHistory.map((item) => (
                        <div
                          key={item.url + item.timestamp}
                          className="flex items-center justify-between p-2 rounded-md bg-secondary/50 hover:bg-secondary cursor-pointer"
                          onClick={() => analyzeUrlAndUpdateUI(item.url)}
                        >
                          <div className="flex-1 min-w-0">
                            <p className="font-medium truncate">{item.url}</p>
                            <p className="text-xs text-muted-foreground">{formatDate(item.timestamp)}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            {getRiskBadge(item.riskLevel)}
                            <button
                              className="text-muted-foreground hover:text-destructive"
                              onClick={(e) => removeHistoryItem(item.url, e)}
                            >
                              <X className="h-4 w-4" />
                              <span className="sr-only">Remove</span>
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="mt-3 flex justify-end">
                      <Button variant="outline" size="sm" onClick={clearHistory}>
                        Clear History
                      </Button>
                    </div>
                  </>
                )}
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {results && (
        <div className="space-y-6">
          {/* Main Results Card */}
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
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div className="md:col-span-2">
                  <h3 className="text-lg font-medium mb-2">Risk Score</h3>
                  <div className="flex items-center gap-4">
                    <div className="w-full flex-1">
                      <Progress value={results.features.risk_score} className="h-6">
                        <div
                          className={`h-full ${getScoreColor(results.features.risk_score)} transition-all duration-500`}
                          style={{ width: `${results.features.risk_score}%` }}
                        ></div>
                      </Progress>
                    </div>
                    <span className="text-2xl font-bold whitespace-nowrap">{results.features.risk_score}/100</span>
                  </div>
                  <p className="mt-2 text-sm text-muted-foreground">
                    Higher score means the URL is more likely to be legitimate.
                  </p>
                </div>

                <div>
                  <h3 className="text-lg font-medium mb-2">ML Confidence</h3>
                  <div className="text-3xl font-bold">{(results.features.hf_confidence * 100).toFixed(2)}%</div>

                </div>
              </div>
            </CardContent>
          </Card>

          {/* Detailed Analysis Tabs */}
          <Card>
            <CardContent className="pt-6">
              <Tabs defaultValue="features" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="features">All Features</TabsTrigger>
                  <TabsTrigger value="security">Security</TabsTrigger>
                  <TabsTrigger value="patterns">Patterns</TabsTrigger>
                  <TabsTrigger value="raw">Raw Data</TabsTrigger>
                </TabsList>

                <TabsContent value="features" className="pt-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {getFeatureCard(
                      "Domain Age",
                      `${results.features.domain_age_days} days`,
                      results.features.domain_age_days > 365 ? "Established domain" : "Recently registered",
                      <Globe className="h-4 w-4 text-muted-foreground" />,
                    )}

                    {getFeatureCard(
                      "SSL Certificate",
                      `${results.features.ssl_valid_days} days`,
                      results.features.ssl_valid_days > 0 ? "Valid certificate" : "Invalid or missing",
                      <Lock className="h-4 w-4 text-muted-foreground" />,
                    )}

                    {getFeatureCard(
                      "URL Length",
                      `${results.features.url_length} chars`,
                      "Total character count",
                      <Eye className="h-4 w-4 text-muted-foreground" />,
                    )}

                    {getFeatureCard(
                      "Country",
                      results.features.country || "Unknown",
                      "Server location",
                      <Globe className="h-4 w-4 text-muted-foreground" />,
                    )}

                    {getFeatureCard(
                      "Min Levenshtein",
                      results.features.min_levenshtein.toString(),
                      "Distance to known domains",
                      <Activity className="h-4 w-4 text-muted-foreground" />,
                    )}

                    {getFeatureCard(
                      "HF Confidence",
                      `${(results.features.hf_confidence * 100).toFixed(4)}%`,
                      "Machine learning confidence",
                      <Zap className="h-4 w-4 text-muted-foreground" />,
                    )}

                    {getFeatureCard(
                      "HF Phishing",
                      results.features.hf_phishing === 1 ? "PHISHING" : "LEGITIMATE",
                      "ML classification result",
                      <Database className="h-4 w-4 text-muted-foreground" />,
                    )}

                    {getFeatureCard(
                      "Risk Level",
                      results.features.risk_level,
                      "Overall risk assessment",
                      <Shield className="h-4 w-4 text-muted-foreground" />,
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="security" className="pt-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Bad IP Address</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(results.features.bad_ip, "Malicious IP", "Clean IP")}
                        <p className="text-xs text-muted-foreground mt-2">IP address reputation check</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Dynamic DNS</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(results.features.dynamic_dns, "Dynamic DNS", "Static DNS")}
                        <p className="text-xs text-muted-foreground mt-2">DNS configuration type</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">In Phishing Database</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(results.features.phish_in_database, "Known Phishing", "Not in Database")}
                        <p className="text-xs text-muted-foreground mt-2">Previously reported as phishing</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Phishing Valid</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(results.features.phish_valid, "Valid Phishing", "Not Valid Phishing")}
                        <p className="text-xs text-muted-foreground mt-2">Validated phishing status</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">SSL Certificate</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{results.features.ssl_valid_days}</div>
                        <p className="text-xs text-muted-foreground">Days until SSL expiration</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Country Code</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{results.features.country || "UNK"}</div>
                        <p className="text-xs text-muted-foreground">Server location identifier</p>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="patterns" className="pt-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Login Form</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(results.features.login_form, "Login Form Present", "No Login Form")}
                        <p className="text-xs text-muted-foreground mt-2">Presence of authentication forms</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">OAuth Suspicious</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(results.features.oauth_suspicious, "Suspicious OAuth", "Normal OAuth")}
                        <p className="text-xs text-muted-foreground mt-2">OAuth implementation analysis</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Redirect Suspicious</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(
                          results.features.redirect_suspicious,
                          "Suspicious Redirects",
                          "Normal Redirects",
                        )}
                        <p className="text-xs text-muted-foreground mt-2">Redirection pattern analysis</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Special Characters</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(
                          results.features.special_characters,
                          "Special Chars Present",
                          "No Special Chars",
                        )}
                        <p className="text-xs text-muted-foreground mt-2">Unusual character usage</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Digit Substitution</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(
                          results.features.digit_substitution,
                          "Digit Substitution",
                          "No Digit Substitution",
                        )}
                        <p className="text-xs text-muted-foreground mt-2">Numbers replacing letters</p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Excessive Subdomains</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {getBooleanBadge(
                          results.features.excessive_subdomains,
                          "Too Many Subdomains",
                          "Normal Subdomains",
                        )}
                        <p className="text-xs text-muted-foreground mt-2">Subdomain structure analysis</p>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="raw" className="pt-4">
                  <Card>
                    <CardHeader>
                      <CardTitle>Complete API Response</CardTitle>
                      <CardDescription>Raw JSON data from the analysis API</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <pre className="bg-secondary p-4 rounded-md overflow-auto text-sm">
                        {JSON.stringify(results, null, 2)}
                      </pre>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      )}
    </main>
  )
}
