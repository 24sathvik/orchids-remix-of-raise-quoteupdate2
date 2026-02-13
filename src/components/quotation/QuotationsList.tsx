"use client"

import { useEffect, useState } from "react"
import { ArrowLeft, Search, Calendar, User, Download, RefreshCw } from "lucide-react"
import { toast } from "sonner"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { createClient } from "@/lib/supabase/client"

interface Quotation {
  id: string
  quotation_number: string
  customer_name: string
  grand_total: number
  created_at: string
  pdf_url: string | null
  profiles: {
    full_name: string
  }
}

export default function QuotationsList({ user, userId }: { user: any, userId?: string }) {
  const [quotations, setQuotations] = useState<Quotation[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [search, setSearch] = useState("")
  
  const supabase = createClient()

  useEffect(() => {
    fetchQuotations()
  }, [userId])

  const fetchQuotations = async () => {
    setLoading(true)
    try {
      let query = supabase
        .from("quotations")
        .select(`
          id,
          quotation_number,
          customer_name,
          grand_total,
          created_at,
          pdf_url,
          profiles!created_by (full_name)
        `)

      if (user?.role !== 'admin') {
        if (userId) {
          query = query.eq('created_by', userId)
        } else {
          const { data: { user: authUser } } = await supabase.auth.getUser()
          if (authUser) {
            query = query.eq('created_by', authUser.id)
          }
        }
      }

      const { data, error } = await query.order("created_at", { ascending: false })
      
      if (error) throw error
      setQuotations(data as any)
    } catch (error: any) {
      toast.error(error.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  const handleRefresh = () => {
    setRefreshing(true)
    fetchQuotations()
  }

  const filteredQuotations = quotations.filter(
    (q) =>
      q.customer_name?.toLowerCase().includes(search.toLowerCase()) ||
      q.quotation_number?.toLowerCase().includes(search.toLowerCase()) ||
      q.profiles?.full_name?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link 
            href={user?.role === 'admin' ? "/admin/quotations" : "/"}
            className="flex h-10 w-10 items-center justify-center rounded-xl border border-gray-100 bg-white text-gray-400 hover:text-black hover:shadow-sm transition-all"
          >
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-3xl font-black tracking-tight text-black">
              {user?.role === 'admin' ? 'All Quotations' : 'My Quotations'}
            </h1>
            <p className="text-sm font-medium text-gray-400">
              {user?.role === 'admin' ? 'Monitor all team quotations.' : 'Track your generated quotations.'}
            </p>
          </div>
        </div>
        <Button 
          variant="outline" 
          size="sm" 
          onClick={handleRefresh}
          disabled={refreshing || loading}
          className="rounded-xl gap-2 font-bold"
        >
          <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      <div className="relative flex-1">
        <Search className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
        <Input
          placeholder="Search by customer or quotation number..."
          className="h-12 rounded-xl border-none bg-white pl-11 shadow-sm ring-1 ring-gray-100 focus:ring-black transition-all"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="overflow-x-auto rounded-2xl border-none bg-white shadow-sm ring-1 ring-gray-100">
        <div className="min-w-[800px]">
          <Table>
            <TableHeader>
              <TableRow className="border-gray-50 hover:bg-transparent">
                <TableHead className="h-14 px-8 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Number</TableHead>
                <TableHead className="h-14 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Customer</TableHead>
                {user?.role === 'admin' && <TableHead className="h-14 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Salesperson</TableHead>}
                <TableHead className="h-14 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Amount</TableHead>
                <TableHead className="h-14 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Date</TableHead>
                <TableHead className="h-14 px-8 text-right text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={user?.role === 'admin' ? 6 : 5} className="h-32 text-center text-sm font-medium text-gray-400">
                    Fetching quotation history...
                  </TableCell>
                </TableRow>
              ) : filteredQuotations.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={user?.role === 'admin' ? 6 : 5} className="h-32 text-center text-sm font-medium text-gray-400">
                    No quotations found.
                  </TableCell>
                </TableRow>
              ) : (
                filteredQuotations.map((q) => (
                  <TableRow key={q.id} className="border-gray-50 group hover:bg-gray-50/50 transition-colors">
                    <TableCell className="px-8 py-5 font-mono text-xs font-bold text-black">{q.quotation_number}</TableCell>
                    <TableCell className="font-bold text-black">{q.customer_name}</TableCell>
                    {user?.role === 'admin' && (
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-gray-100 text-[8px] font-black text-black">
                            {q.profiles?.full_name?.[0] || 'S'}
                          </div>
                          <span className="text-xs font-bold text-gray-600">{q.profiles?.full_name}</span>
                        </div>
                      </TableCell>
                    )}
                    <TableCell className="font-black text-black">₹{q.grand_total?.toLocaleString()}</TableCell>
                    <TableCell className="text-xs font-bold text-gray-400 uppercase tracking-tighter">
                      {new Date(q.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="px-8 text-right">
                      {q.pdf_url && (
                        <a
                          href={q.pdf_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex h-9 items-center gap-2 rounded-xl border border-gray-100 bg-white px-4 text-xs font-bold text-black shadow-sm transition-all hover:bg-gray-50 active:scale-95"
                        >
                          <Download className="h-3.5 w-3.5" />
                          View PDF
                        </a>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  )
}
