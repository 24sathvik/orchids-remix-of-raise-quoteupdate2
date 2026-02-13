"use client"

import { useState, useEffect, useMemo, useCallback } from "react"
import {
  Plus,
  Trash2,
  Download,
  Trash,
  Search,
  User,
  Hash,
  FileText,
  Settings as SettingsIcon,
  LogOut,
  ChevronRight,
  Package,
  CheckCircle2,
  PlusCircle,
  Menu,
  X,
  ChevronDown
} from "lucide-react"
import { toast } from "sonner"
import Image from "next/image"
import Link from "next/link"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import {
  Badge
} from "@/components/ui/badge"
import { generateQuotationPDF } from "@/lib/pdf-service"
import { createClient } from "@/lib/supabase/client"

interface Product {
  id: string
  name: string
  description: string
  price: number
  image_url: string | null
  sku: string
  addons?: { name: string; price: number; active?: boolean }[]
  specs?: { key: string; value: string }[]
  features?: string[]
  category?: string
  image_format?: 'wide' | 'tall'
}

interface QuotationItem {
  id: string
  product_id: string
  name: string
  description: string
  qty: number
  price: number
  image_url: string | null
  sku: string
  selectedAddons?: { name: string; price: number }[]
  specs?: { key: string; value: string }[]
  features?: string[]
  image_format?: 'wide' | 'tall'
}

interface Term {
  id: string
  text: string
  selected: boolean
}

interface QuotationBuilderProps {
  initialProducts: Product[]
  settings: any
  user: any
}

type Currency = 'INR' | 'USD'

const DEFAULT_TERMS = [
  "Packaging & Forwarding: Extra As Applicable",
  "Fright: To Pay / Extra as applicable",
  "DELIVERY: We deliver the order in 3-4 Weeks from the date of receipt of purchase order",
  "INSTALLATION: Fees extra as applicable",
  "PAYMENT: 100% payment at the time of proforma invoice prior to dispatch.",
  "WARRANTY: One year warranty from the date of dispatch",
  "GOVERNING LAW: These Terms and Conditions and any action related hereto shall be governed, controlled, interpreted and defined by and under the laws of the State of Telangana",
  "MODIFICATION: Any modification of these Terms and Conditions shall be valid only if it is in writing and signed by the authorized representatives of both Supplier and Customer."
]

export default function QuotationBuilder({ initialProducts, settings, user }: QuotationBuilderProps) {
  const [items, setItems] = useState<QuotationItem[]>([])
  const [customer, setCustomer] = useState({
    name: "",
    phone: "",
    email: "",
    address: "",
  })
  const [meta, setMeta] = useState({
    number: "RLE-...",
    date: new Date().toISOString().split("T")[0],
    validity_days: 30,
  })
  const [discount, setDiscount] = useState(0)
  const [isProductOpen, setIsProductOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [isSidebarOpen, setIsSidebarOpen] = useState(false)
  const [terms, setTerms] = useState<Term[]>(
    DEFAULT_TERMS.map((t, i) => ({ id: `term-${i}`, text: t, selected: true }))
  )
  const [currency, setCurrency] = useState<Currency>('INR')

  const supabase = useMemo(() => createClient(), [])

  // Fetch next sequential quotation number
  useEffect(() => {
    const fetchNextQuotationNumber = async () => {
      try {
        const { data: lastQuotation } = await supabase
          .from('quotations')
          .select('quotation_number')
          .order('created_at', { ascending: false })
          .limit(1)
          .single()

        let nextNumber = 'RLE-101'
        if (lastQuotation?.quotation_number) {
          const match = lastQuotation.quotation_number.match(/RLE-(\d+)/)
          if (match) {
            const num = parseInt(match[1]) + 1
            nextNumber = `RLE-${num}`
          }
        }

        setMeta(prev => ({ ...prev, number: nextNumber }))
      } catch (error) {
        console.error('Failed to fetch quotation number:', error)
        setMeta(prev => ({ ...prev, number: 'RLE-101' }))
      }
    }

    fetchNextQuotationNumber()
  }, [supabase])

  // Load draft
  useEffect(() => {
    const draft = localStorage.getItem("quotation_draft")
    if (draft) {
      try {
        const parsed = JSON.parse(draft)
        setItems(parsed.items || [])
        setCustomer(parsed.customer || { name: "", phone: "", email: "", address: "" })
        // Don't load quotation number from draft - always use fresh sequential number
        if (parsed.meta?.date) {
          setMeta(prev => ({ ...prev, date: parsed.meta.date, validity_days: parsed.meta.validity_days || 30 }))
        }
        setDiscount(parsed.discount || 0)
        if (parsed.terms) {
          setTerms(parsed.terms)
        }
      } catch (e) {
        console.error("Failed to load draft", e)
      }
    }
  }, [])

  // Save draft with debounce
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      localStorage.setItem(
        "quotation_draft",
        JSON.stringify({ items, customer, meta, discount, terms })
      )
    }, 1000) // Debounce for 1 second

    return () => clearTimeout(timeoutId)
  }, [items, customer, meta, discount, terms])

  const totals = useMemo(() => {
    const subtotal = items.reduce((acc, item) => {
      const addonsPrice = item.selectedAddons?.reduce((sum, addon) => sum + addon.price, 0) || 0
      return acc + (item.price + addonsPrice) * item.qty
    }, 0)

    // Tax completely removed as per request
    const tax_amount = 0
    const grand_total = Math.max(0, subtotal - discount)

    return { subtotal, tax_amount, grand_total }
  }, [items, discount])

  const addItem = useCallback((product: Product) => {
    const newItem: QuotationItem = {
      id: Math.random().toString(36).slice(2),
      product_id: product.id,
      name: product.name,
      description: product.description,
      qty: 1,
      price: product.price,
      image_url: product.image_url,
      sku: product.sku,
      // Add all addons by default as requested
      selectedAddons: product.addons ? product.addons.map(a => ({ name: a.name, price: a.price })) : [],
      specs: product.specs || [],
      features: product.features || [],
      image_format: product.image_format || 'wide'
    }
    setItems(prev => [...prev, newItem])
    setIsProductOpen(false)
    toast.success(`${product.name} added with all addons selected`)
  }, [])

  const updateItem = useCallback((id: string, updates: Partial<QuotationItem>) => {
    setItems(items => items.map((item) => (item.id === id ? { ...item, ...updates } : item)))
  }, [])

  const removeItem = useCallback((id: string) => {
    setItems(items => items.filter((item) => item.id !== id))
  }, [])

  const toggleAddon = useCallback((itemId: string, addon: { name: string; price: number }) => {
    setItems(items => items.map(item => {
      if (item.id === itemId) {
        const currentAddons = item.selectedAddons || []
        const exists = currentAddons.find(a => a.name === addon.name)
        const nextAddons = exists
          ? currentAddons.filter(a => a.name !== addon.name)
          : [...currentAddons, addon]
        return { ...item, selectedAddons: nextAddons }
      }
      return item
    }))
  }, [])

  const toggleTerm = useCallback((termId: string) => {
    setTerms(terms => terms.map(t => t.id === termId ? { ...t, selected: !t.selected } : t))
  }, [])

  const clearQuotation = () => {
    if (!confirm("Are you sure you want to clear this quotation?")) return
    setItems([])
    setCustomer({ name: "", phone: "", email: "", address: "" })
    // Fetch fresh sequential number instead of random one
    const triggerRefetch = async () => {
      const { data: lastQuotation } = await supabase
        .from('quotations')
        .select('quotation_number')
        .order('created_at', { ascending: false })
        .limit(1)
        .single()

      let nextNumber = 'RLE-101'
      if (lastQuotation?.quotation_number) {
        const match = lastQuotation.quotation_number.match(/RLE-(\d+)/)
        if (match) {
          const num = parseInt(match[1]) + 1
          nextNumber = `RLE-${num}`
        }
      }
      setMeta({
        number: nextNumber,
        date: new Date().toISOString().split("T")[0],
        validity_days: 30,
      })
    }
    triggerRefetch()
    setDiscount(0)
    setTerms(DEFAULT_TERMS.map((t, i) => ({ id: `term-${i}`, text: t, selected: true })))
    localStorage.removeItem("quotation_draft")
  }

  const handleDownload = async () => {
    if (!customer.name) {
      toast.error("Please enter customer name")
      return
    }
    if (items.length === 0) {
      toast.error("Please add at least one item")
      return
    }

    setSaving(true)
    try {
      if (!user || !user.id) {
        toast.error("User session not found. Please log in again.")
        window.location.href = "/auth/login"
        return
      }

      // We already have user in props, no need to call getSession which might abort
      const { data, error } = await supabase.from("quotations").insert({
        quotation_number: meta.number,
        created_by: user.id,
        customer_name: customer.name,
        customer_phone: customer.phone,
        customer_email: customer.email,
        customer_address: customer.address,
        items_json: items,
        subtotal: totals.subtotal,
        tax_amount: 0,
        tax_total: 0,
        total_amount: totals.grand_total,
        discount_total: discount,
        grand_total: totals.grand_total,
      }).select().single()

      if (error) throw error

      const pdfBlob = await generateQuotationPDF({
        quotation: data,
        items: items, // Use items directly as they are already converted in UI
        settings,
        user,
        selectedTerms: terms.filter(t => t.selected).map(t => ({ title: t.text.split(':')[0], text: t.text.split(':').slice(1).join(':').trim() })),
        currency
      })

      const fileName = `${data.quotation_number}_${data.id}.pdf`
      const { error: uploadError } = await supabase.storage
        .from("quotations")
        .upload(fileName, pdfBlob, {
          contentType: "application/pdf",
          upsert: true
        })

      if (uploadError) {
        console.error("PDF Upload Error:", uploadError)
      } else {
        const { data: { publicUrl } } = supabase.storage
          .from("quotations")
          .getPublicUrl(fileName)

        await supabase
          .from("quotations")
          .update({ pdf_url: publicUrl })
          .eq("id", data.id)
      }

      toast.success("Quotation saved and PDF generated")
    } catch (err: any) {
      toast.error(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex min-h-screen bg-[#FDFDFD]">
      {/* Mobile Sidebar Overlay */}
      {isSidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 border-r border-gray-100 bg-white transition-transform duration-300 lg:translate-x-0 ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-full flex-col">
          <div className="flex h-20 items-center justify-between px-6">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-black text-white">
                <span className="font-black">R</span>
              </div>
              <span className="text-sm font-black tracking-tighter">RAISE LABS</span>
            </div>
            <button className="lg:hidden" onClick={() => setIsSidebarOpen(false)}>
              <X className="h-5 w-5" />
            </button>
          </div>

          <nav className="flex-1 space-y-1 px-4 py-6">
            <Link
              href="/"
              className="flex items-center gap-3 rounded-xl bg-black px-4 py-3 text-sm font-semibold text-white shadow-lg transition-all"
            >
              <Plus className="h-5 w-5" />
              New Quotation
            </Link>
            <Link
              href={user?.role === 'admin' ? "/admin/quotations" : "/quotations"}
              className="flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium text-gray-500 hover:bg-gray-50 hover:text-black transition-all"
            >
              <Hash className="h-5 w-5" />
              Quotations
            </Link>
            <div className="my-6 h-px bg-gray-50" />
            <Link
              href={user?.role === 'admin' ? "/admin/products" : "/catalog"}
              className="flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium text-gray-500 hover:bg-gray-50 hover:text-black transition-all"
            >
              <Package className="h-5 w-5" />
              Catalog
            </Link>
            {user?.role === 'admin' && (
              <Link
                href="/admin/users"
                className="flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium text-gray-500 hover:bg-gray-50 hover:text-black transition-all"
              >
                <User className="h-5 w-5" />
                Team
              </Link>
            )}
          </nav>

          <div className="border-t border-gray-50 p-4">
            <div className="flex items-center gap-3 px-2 py-3 rounded-xl bg-gray-50/50">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-black text-[10px] font-bold text-white uppercase">
                {user?.full_name?.[0] || 'A'}
              </div>
              <div className="flex-1 overflow-hidden">
                <p className="truncate text-xs font-bold text-black">{user?.full_name || 'Admin'}</p>
                <p className="truncate text-[10px] font-medium text-gray-400 uppercase tracking-wider">Professional</p>
              </div>
              <Link href="/auth/signout" className="text-gray-400 hover:text-red-500 transition-colors">
                <LogOut className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 transition-all lg:pl-64">
        {/* Mobile Header */}
        <div className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-gray-100 bg-white/80 px-6 backdrop-blur-md lg:hidden">
          <button onClick={() => setIsSidebarOpen(true)}>
            <Menu className="h-6 w-6" />
          </button>
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-black text-white">
              <span className="text-xs font-black">R</span>
            </div>
            <span className="text-xs font-black tracking-tighter">RAISE LABS</span>
          </div>
          <div className="w-6" />
        </div>

        <div className="mx-auto max-w-5xl px-4 py-8 lg:px-10 lg:py-10">
          <header className="mb-10 flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1">
              <h1 className="text-3xl font-black tracking-tight text-black">
                Quotation <span className="text-gray-300">Generator</span>
              </h1>
              <p className="text-sm font-medium text-gray-400">Generate professional pharmaceutical product quotes</p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="outline" onClick={clearQuotation} className="h-11 rounded-xl px-5 font-bold border-gray-200 hover:bg-red-50 hover:text-red-600 transition-all">
                Reset
              </Button>
              <Button
                disabled={saving}
                onClick={handleDownload}
                className="h-11 flex-1 rounded-xl bg-black px-8 font-bold text-white shadow-xl shadow-black/20 hover:bg-black/90 active:scale-95 transition-all sm:flex-none"
              >
                {saving ? "Generating..." : "Download PDF"}
              </Button>
            </div>
          </header>

          <div className="grid gap-8">
            {/* Customer & Meta */}
            <div className="grid gap-6 md:grid-cols-2">
              <Card className="border-none bg-white shadow-sm ring-1 ring-gray-100 rounded-2xl">
                <CardHeader className="pb-4">
                  <CardTitle className="text-sm font-black uppercase tracking-widest text-gray-400">Client Details</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label className="text-xs font-bold text-gray-700">Client Name</Label>
                      <Input
                        className="h-11 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white transition-all"
                        value={customer.name}
                        onChange={(e) => setCustomer({ ...customer, name: e.target.value })}
                        placeholder="e.g. Acme Corp"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs font-bold text-gray-700">Phone</Label>
                      <Input
                        className="h-11 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white transition-all"
                        value={customer.phone}
                        onChange={(e) => setCustomer({ ...customer, phone: e.target.value })}
                        placeholder="+91..."
                      />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs font-bold text-gray-700">Email Address</Label>
                    <Input
                      className="h-11 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white transition-all"
                      value={customer.email}
                      onChange={(e) => setCustomer({ ...customer, email: e.target.value })}
                      placeholder="client@company.com"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs font-bold text-gray-700">Shipping Address</Label>
                    <Input
                      className="h-11 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white transition-all"
                      value={customer.address}
                      onChange={(e) => setCustomer({ ...customer, address: e.target.value })}
                      placeholder="Full address details"
                    />
                  </div>
                </CardContent>
              </Card>

              <Card className="border-none bg-white shadow-sm ring-1 ring-gray-100 rounded-2xl">
                <CardHeader className="pb-4">
                  <CardTitle className="text-sm font-black uppercase tracking-widest text-gray-400">Quotation Meta</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-1.5">
                    <Label className="text-xs font-bold text-gray-700">Quotation ID</Label>
                    <Input
                      className="h-11 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white transition-all font-mono"
                      value={meta.number}
                      onChange={(e) => setMeta({ ...meta, number: e.target.value })}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs font-bold text-gray-700">Issue Date</Label>
                    <Input
                      type="date"
                      className="h-11 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white transition-all"
                      value={meta.date}
                      onChange={(e) => setMeta({ ...meta, date: e.target.value })}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs font-bold text-gray-700">Validity (Days)</Label>
                    <Input
                      type="number"
                      className="h-11 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white transition-all"
                      value={meta.validity_days}
                      onChange={(e) => setMeta({ ...meta, validity_days: parseInt(e.target.value) || 30 })}
                      min="1"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs font-bold text-gray-700">Currency</Label>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          if (currency !== 'INR') {
                            const conversionRate = 83
                            setItems(items.map(item => ({
                              ...item,
                              price: Math.round(item.price * conversionRate),
                              selectedAddons: item.selectedAddons?.map(addon => ({
                                ...addon,
                                price: Math.round(addon.price * conversionRate)
                              }))
                            })))
                            setDiscount(prev => Math.round(prev * conversionRate))
                            setCurrency('INR')
                          }
                        }}
                        className={`flex-1 h-11 rounded-xl font-bold transition-all ${currency === 'INR'
                          ? 'bg-black text-white'
                          : 'bg-gray-50 text-gray-500 hover:bg-gray-100'
                          }`}
                      >
                        INR
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          if (currency !== 'USD') {
                            const conversionRate = 83
                            setItems(items.map(item => ({
                              ...item,
                              price: Number((item.price / conversionRate).toFixed(2)),
                              selectedAddons: item.selectedAddons?.map(addon => ({
                                ...addon,
                                price: Number((addon.price / conversionRate).toFixed(2))
                              }))
                            })))
                            setDiscount(prev => Number((prev / conversionRate).toFixed(2)))
                            setCurrency('USD')
                          }
                        }}
                        className={`flex-1 h-11 rounded-xl font-bold transition-all ${currency === 'USD'
                          ? 'bg-black text-white'
                          : 'bg-gray-50 text-gray-500 hover:bg-gray-100'
                          }`}
                      >
                        USD
                      </button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Line Items */}
            <Card className="border-none bg-white shadow-sm ring-1 ring-gray-100 rounded-2xl overflow-hidden">
              <CardHeader className="flex flex-col gap-4 border-b border-gray-50 p-6 sm:flex-row sm:items-center sm:justify-between">
                <CardTitle className="text-sm font-black uppercase tracking-widest text-gray-400">Line Items</CardTitle>
                <Popover open={isProductOpen} onOpenChange={setIsProductOpen}>
                  <PopoverTrigger asChild>
                    <Button variant="outline" className="h-10 w-full rounded-xl gap-2 border-gray-200 font-bold hover:bg-black hover:text-white transition-all sm:w-auto">
                      <Plus className="h-4 w-4" /> Add Product
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-[calc(100vw-32px)] max-w-[400px] p-0 rounded-2xl shadow-2xl border-none" align="end">
                    <Command className="rounded-2xl">
                      <CommandInput placeholder="Search products..." className="h-12 border-none focus:ring-0" />
                      <CommandList className="max-h-[300px]">
                        <CommandEmpty>No results found.</CommandEmpty>
                        <CommandGroup className="p-2">
                          {initialProducts.map((product) => (
                            <CommandItem
                              key={product.id}
                              onSelect={() => addItem(product)}
                              className="flex items-center gap-3 rounded-xl p-3 cursor-pointer aria-selected:bg-gray-50 transition-all"
                            >
                              <div className="relative h-12 w-12 overflow-hidden rounded-xl border border-gray-100 bg-white">
                                {product.image_url && <Image src={product.image_url} alt={product.name} fill className="object-contain p-1" />}
                              </div>
                              <div className="flex flex-col">
                                <span className="text-sm font-bold text-black">{product.name}</span>
                                <span className="text-[10px] font-bold text-gray-400 uppercase">{currency === 'INR' ? '₹' : '$'}{product.price.toLocaleString()}</span>
                              </div>
                            </CommandItem>
                          ))}
                        </CommandGroup>
                      </CommandList>
                    </Command>
                  </PopoverContent>
                </Popover>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  {/* Desktop Table View */}
                  <Table className="hidden md:table">
                    <TableHeader>
                      <TableRow className="border-gray-50 hover:bg-transparent">
                        <TableHead className="px-8 py-4 text-[10px] font-bold uppercase tracking-widest text-gray-400">Item Details</TableHead>
                        <TableHead className="w-[120px] text-center text-[10px] font-bold uppercase tracking-widest text-gray-400">Qty</TableHead>
                        <TableHead className="w-[150px] text-[10px] font-bold uppercase tracking-widest text-gray-400">Unit Price</TableHead>
                        <TableHead className="w-[150px] text-right text-[10px] font-bold uppercase tracking-widest text-gray-400">Total Amount</TableHead>
                        <TableHead className="w-[80px]"></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {items.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={5} className="h-48 text-center text-sm font-medium text-gray-400">
                            Add products to build your quotation
                          </TableCell>
                        </TableRow>
                      ) : (
                        items.map((item) => (
                          <TableRow key={item.id} className="border-gray-50 group hover:bg-gray-50/30 transition-colors">
                            <TableCell className="px-8 py-6">
                              <div className="flex items-start gap-4">
                                <div className="relative h-16 w-16 flex-shrink-0 overflow-hidden rounded-xl border border-gray-100 bg-white shadow-sm">
                                  {item.image_url && <Image src={item.image_url} alt={item.name} fill className="object-contain p-2" />}
                                </div>
                                <div className="space-y-4 flex-1">
                                  <div className="space-y-1">
                                    <p className="text-sm font-black text-black uppercase tracking-tight">{item.name}</p>
                                    <p className="text-xs text-gray-400 line-clamp-1">{item.description}</p>
                                  </div>

                                  {/* Addons Selection with Checkboxes */}
                                  <div className="space-y-2">
                                    <p className="text-[10px] font-black text-gray-300 uppercase tracking-widest">Available Addons</p>
                                    <div className="flex flex-wrap gap-3">
                                      {initialProducts.find(p => p.id === item.product_id)?.addons?.map((addon) => (
                                        <div
                                          key={addon.name}
                                          className="flex items-center space-x-2 bg-gray-50/50 px-3 py-1.5 rounded-lg border border-gray-100 hover:border-black/10 transition-colors cursor-pointer"
                                          onClick={() => toggleAddon(item.id, addon)}
                                        >
                                          <Checkbox
                                            id={`addon-${item.id}-${addon.name}`}
                                            checked={!!item.selectedAddons?.find(a => a.name === addon.name)}
                                            onCheckedChange={() => toggleAddon(item.id, addon)}
                                            className="data-[state=checked]:bg-black data-[state=checked]:border-black"
                                          />
                                          <label
                                            htmlFor={`addon-${item.id}-${addon.name}`}
                                            className="text-[10px] font-bold text-gray-600 cursor-pointer"
                                          >
                                            {addon.name} (+₹{addon.price.toLocaleString()})
                                          </label>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Input
                                type="number"
                                min="1"
                                className="mx-auto h-10 w-20 rounded-xl border-gray-100 bg-gray-50/50 text-center font-bold focus:bg-white"
                                value={item.qty}
                                onChange={(e) => updateItem(item.id, { qty: parseInt(e.target.value) || 1 })}
                              />
                            </TableCell>
                            <TableCell>
                              <div className="relative">
                                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[10px] font-bold text-gray-400">₹</span>
                                <Input
                                  type="number"
                                  className="h-10 w-full rounded-xl border-gray-100 bg-gray-50/50 pl-6 pr-2 font-bold focus:bg-white"
                                  value={item.price}
                                  onChange={(e) => updateItem(item.id, { price: parseFloat(e.target.value) || 0 })}
                                />
                              </div>
                            </TableCell>
                            <TableCell className="text-right text-sm font-black text-black">
                              ₹{((item.price + (item.selectedAddons?.reduce((s, a) => s + a.price, 0) || 0)) * item.qty).toLocaleString()}
                            </TableCell>
                            <TableCell className="px-8">
                              <button
                                onClick={() => removeItem(item.id)}
                                className="flex h-8 w-8 items-center justify-center rounded-lg text-gray-200 hover:bg-red-50 hover:text-red-500 transition-all"
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>

                  {/* Mobile Card View */}
                  <div className="flex flex-col gap-4 p-4 md:hidden">
                    {items.length === 0 ? (
                      <div className="h-48 flex items-center justify-center text-center text-sm font-medium text-gray-400 bg-gray-50/50 rounded-xl">
                        Add products to build your quotation
                      </div>
                    ) : (
                      items.map((item) => (
                        <div key={item.id} className="relative flex flex-col gap-4 rounded-xl border border-gray-100 bg-white p-4 shadow-sm">
                          <div className="flex items-start gap-4">
                            <div className="relative h-20 w-20 flex-shrink-0 overflow-hidden rounded-xl border border-gray-100 bg-white">
                              {item.image_url && <Image src={item.image_url} alt={item.name} fill className="object-contain p-2" />}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="pr-8">
                                <p className="text-sm font-black text-black uppercase tracking-tight truncate">{item.name}</p>
                                <p className="text-xs text-gray-400 line-clamp-2 mt-1">{item.description}</p>
                              </div>
                            </div>
                            <button
                              onClick={() => removeItem(item.id)}
                              className="absolute top-4 right-4 flex h-8 w-8 items-center justify-center rounded-lg text-gray-200 hover:bg-red-50 hover:text-red-500 transition-all"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>

                          <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-1">
                              <Label className="text-[10px] font-bold uppercase text-gray-400">Qty</Label>
                              <Input
                                type="number"
                                min="1"
                                className="h-10 w-full rounded-xl border-gray-100 bg-gray-50/50 text-center font-bold focus:bg-white"
                                value={item.qty}
                                onChange={(e) => updateItem(item.id, { qty: parseInt(e.target.value) || 1 })}
                              />
                            </div>
                            <div className="space-y-1">
                              <Label className="text-[10px] font-bold uppercase text-gray-400">Unit Price</Label>
                              <div className="relative">
                                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[10px] font-bold text-gray-400">₹</span>
                                <Input
                                  type="number"
                                  className="h-10 w-full rounded-xl border-gray-100 bg-gray-50/50 pl-6 pr-2 font-bold focus:bg-white"
                                  value={item.price}
                                  onChange={(e) => updateItem(item.id, { price: parseFloat(e.target.value) || 0 })}
                                />
                              </div>
                            </div>
                          </div>

                          {/* Addons Mobile */}
                          {initialProducts.find(p => p.id === item.product_id)?.addons && (initialProducts.find(p => p.id === item.product_id)?.addons?.length || 0) > 0 && (
                            <div className="space-y-2 pt-2 border-t border-gray-50">
                              <p className="text-[10px] font-black text-gray-300 uppercase tracking-widest">Addons</p>
                              <div className="flex flex-wrap gap-2">
                                {initialProducts.find(p => p.id === item.product_id)?.addons?.map((addon) => (
                                  <div
                                    key={addon.name}
                                    className={`flex items-center space-x-2 px-3 py-2 rounded-lg border transition-colors cursor-pointer ${item.selectedAddons?.find(a => a.name === addon.name)
                                      ? 'bg-black text-white border-black'
                                      : 'bg-gray-50 border-gray-100 text-gray-600'
                                      }`}
                                    onClick={() => toggleAddon(item.id, addon)}
                                  >
                                    <span className="text-[10px] font-bold">
                                      {addon.name} (+₹{addon.price.toLocaleString()})
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          <div className="flex items-center justify-between pt-2 border-t border-gray-50">
                            <span className="text-xs font-bold text-gray-400 uppercase">Subtotal</span>
                            <span className="text-lg font-black text-black">
                              ₹{((item.price + (item.selectedAddons?.reduce((s, a) => s + a.price, 0) || 0)) * item.qty).toLocaleString()}
                            </span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </CardContent>
              {items.length > 0 && (
                <div className="bg-gray-50/50 p-8">
                  <div className="ml-auto max-w-sm space-y-4">
                    <div className="flex justify-between text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">
                      <span>Subtotal</span>
                      <span className="text-black">{currency === 'INR' ? '₹' : '$'}{totals.subtotal.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">
                      <span>Adjustment</span>
                      <div className="relative">
                        <span className="absolute left-2 top-1/2 -translate-y-1/2 text-[10px] font-bold text-gray-400">-{currency === 'INR' ? '₹' : '$'}</span>
                        <Input
                          type="number"
                          className="h-8 w-28 rounded-lg border-gray-200 bg-white pl-7 pr-2 text-right font-bold text-black"
                          value={discount}
                          onChange={(e) => setDiscount(parseFloat(e.target.value) || 0)}
                        />
                      </div>
                    </div>
                    <div className="h-px bg-gray-100" />
                    <div className="flex items-end justify-between">
                      <span className="text-[10px] font-black uppercase tracking-[0.3em] text-black">Grand Total</span>
                      <span className="text-3xl font-black tracking-tighter text-black">{currency === 'INR' ? '₹' : '$'}{totals.grand_total.toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              )}
            </Card>

            {/* Terms & Conditions Section */}
            <Card className="border-none bg-white shadow-sm ring-1 ring-gray-100 rounded-2xl overflow-hidden">
              <CardHeader className="border-b border-gray-50 p-6">
                <CardTitle className="text-sm font-black uppercase tracking-widest text-gray-400">Terms & Conditions</CardTitle>
              </CardHeader>
              <CardContent className="p-6">
                <div className="space-y-4">
                  {terms.map((term) => (
                    <div
                      key={term.id}
                      className="flex items-start space-x-3 p-3 rounded-xl hover:bg-gray-50/50 transition-colors group cursor-pointer"
                      onClick={() => toggleTerm(term.id)}
                    >
                      <Checkbox
                        id={term.id}
                        checked={term.selected}
                        onCheckedChange={() => toggleTerm(term.id)}
                        className="mt-1 data-[state=checked]:bg-black data-[state=checked]:border-black"
                      />
                      <Label
                        htmlFor={term.id}
                        className="text-sm font-medium leading-relaxed text-gray-600 group-hover:text-black transition-colors cursor-pointer"
                      >
                        {term.text}
                      </Label>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  )
}
