"use client"

import { useEffect, useState } from "react"
import { Plus, Search, Edit2, Trash2, Power, PowerOff, Upload, X } from "lucide-react"
import { toast } from "sonner"
import Image from "next/image"

import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { createClient } from "@/lib/supabase/client"

interface Addon {
  name: string
  price: number
  description?: string
  active?: boolean
}

interface Spec {
  key: string
  value: string
}

interface Product {
  id: string
  name: string
  description: string
  price: number
  tax_percent: number
  image_url: string | null
  active: boolean
  category: string
  sku: string
  addons: Addon[]
  specs?: Spec[]
  features?: string[]
  created_at: string
  image_format?: 'wide' | 'tall'
}

interface Category {
  id: string
  name: string
}

export default function ProductsPage() {
  const [products, setProducts] = useState<Product[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState("")
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [selectedProduct, setSelectedProduct] = useState<Product | null>(null)
  const [uploading, setUploading] = useState(false)

  const [formData, setFormData] = useState<Partial<Product>>({
    name: "",
    description: "",
    price: 0,
    tax_percent: 18,
    active: true,
    image_url: null,
    category: "",
    sku: "",
    addons: [],
    specs: [],
    features: [],
    image_format: "wide",
  })

  const supabase = createClient()

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      // Optimized: Parallel fetching with minimal payload
      const [prodRes, catRes] = await Promise.all([
        supabase.from("products").select("*").order("created_at", { ascending: false }),
        supabase.from("categories").select("id, name").order("name")
      ])

      if (prodRes.error) toast.error(prodRes.error.message)
      else setProducts(prodRes.data || [])

      if (catRes.error) toast.error(catRes.error.message)
      else setCategories(catRes.data || [])
    } catch (err: any) {
      toast.error("Failed to load data")
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const dataToSave = {
        ...formData,
        price: Number(formData.price),
        tax_percent: Number(formData.tax_percent),
      }

      if (selectedProduct) {
        const { error } = await supabase
          .from("products")
          .update(dataToSave)
          .eq("id", selectedProduct.id)
        if (error) throw error
        toast.success("Product updated")
      } else {
        const { error } = await supabase
          .from("products")
          .insert(dataToSave)
        if (error) throw error
        toast.success("Product created")
      }
      setIsDialogOpen(false)
      fetchData()
      resetForm()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleToggleStatus = async (product: Product) => {
    try {
      const { error } = await supabase
        .from("products")
        .update({ active: !product.active })
        .eq("id", product.id)
      if (error) throw error
      toast.success(`Product ${product.active ? "deactivated" : "activated"}`)
      fetchData()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure?")) return
    try {
      const { error } = await supabase
        .from("products")
        .delete()
        .eq("id", id)
      if (error) throw error
      toast.success("Product deleted")
      fetchData()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    try {
      const fileExt = file.name.split(".").pop()
      const fileName = `${Math.random()}.${fileExt}`
      const { error: uploadError } = await supabase.storage
        .from("products")
        .upload(fileName, file)
      if (uploadError) throw uploadError
      const { data: { publicUrl } } = supabase.storage.from("products").getPublicUrl(fileName)
      setFormData({ ...formData, image_url: publicUrl })
      toast.success("Image uploaded")
    } catch (err: any) {
      toast.error(err.message)
    } finally {
      setUploading(false)
    }
  }

  const addAddon = () => {
    setFormData({
      ...formData,
      addons: [...(formData.addons || []), { name: "", price: 0, active: true }]
    })
  }

  const removeAddon = (index: number) => {
    const next = [...(formData.addons || [])]
    next.splice(index, 1)
    setFormData({ ...formData, addons: next })
  }

  const updateAddon = (index: number, updates: Partial<Addon>) => {
    const next = [...(formData.addons || [])]
    next[index] = { ...next[index], ...updates }
    setFormData({ ...formData, addons: next })
  }

  const addSpec = () => {
    setFormData({
      ...formData,
      specs: [...(formData.specs || []), { key: "", value: "" }]
    })
  }

  const removeSpec = (index: number) => {
    const next = [...(formData.specs || [])]
    next.splice(index, 1)
    setFormData({ ...formData, specs: next })
  }

  const updateSpec = (index: number, updates: Partial<Spec>) => {
    const next = [...(formData.specs || [])]
    next[index] = { ...next[index], ...updates }
    setFormData({ ...formData, specs: next })
  }

  const addFeature = () => {
    setFormData({
      ...formData,
      features: [...(formData.features || []), ""]
    })
  }

  const removeFeature = (index: number) => {
    const next = [...(formData.features || [])]
    next.splice(index, 1)
    setFormData({ ...formData, features: next })
  }

  const updateFeature = (index: number, value: string) => {
    const next = [...(formData.features || [])]
    next[index] = value
    setFormData({ ...formData, features: next })
  }

  const resetForm = () => {
    setSelectedProduct(null)
    setFormData({
      name: "",
      description: "",
      price: 0,
      tax_percent: 18,
      active: true,
      image_url: null,
      category: "",
      sku: "",
      addons: [],
      specs: [],
      features: [],
      image_format: "wide",
    })
  }

  const filteredProducts = products.filter(p =>
    p.name?.toLowerCase().includes(search.toLowerCase()) ||
    p.category?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Products</h1>
          <p className="text-muted-foreground">Manage your catalog with categories and addons.</p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={(open) => {
          setIsDialogOpen(open)
          if (!open) resetForm()
        }}>
          <DialogTrigger asChild>
            <button className="flex items-center gap-2 rounded-lg bg-black px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-black/90">
              <Plus className="h-4 w-4" />
              Add Product
            </button>
          </DialogTrigger>
          <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto w-[95vw] sm:w-full">
            <form onSubmit={handleSave}>
              <DialogHeader>
                <DialogTitle>{selectedProduct ? "Edit Product" : "Add New Product"}</DialogTitle>
                <DialogDescription>Fill in the product details below.</DialogDescription>
              </DialogHeader>

              <div className="grid gap-6 md:gap-8 py-4 md:grid-cols-2">
                <div className="space-y-6">
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold uppercase tracking-wider text-gray-400">Basic Info</h3>
                    <div className="space-y-2">
                      <Label>Product Name</Label>
                      <Input
                        required
                        value={formData.name}
                        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Category</Label>
                        <Select
                          value={formData.category}
                          onValueChange={(v) => setFormData({ ...formData, category: v })}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select Category" />
                          </SelectTrigger>
                          <SelectContent>
                            {categories.map(c => (
                              <SelectItem key={c.id} value={c.name}>{c.name}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>SKU</Label>
                        <Input
                          value={formData.sku}
                          onChange={(e) => setFormData({ ...formData, sku: e.target.value })}
                        />
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Description</Label>
                      <Textarea
                        rows={3}
                        value={formData.description || ""}
                        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Base Price</Label>
                        <Input
                          type="number"
                          required
                          value={formData.price}
                          onChange={(e) => setFormData({ ...formData, price: parseFloat(e.target.value) })}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Tax %</Label>
                        <Input
                          type="number"
                          required
                          value={formData.tax_percent}
                          onChange={(e) => setFormData({ ...formData, tax_percent: parseFloat(e.target.value) })}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold uppercase tracking-wider text-gray-400">Add-ons</h3>
                      <button type="button" onClick={addAddon} className="text-xs font-bold text-black hover:underline flex items-center gap-1">
                        <Plus className="h-3 w-3" /> Add
                      </button>
                    </div>
                    <div className="space-y-2">
                      {formData.addons?.map((addon, i) => (
                        <div key={i} className="flex gap-2 items-start">
                          <Input
                            placeholder="Name"
                            className="flex-1"
                            value={addon.name}
                            onChange={(e) => updateAddon(i, { name: e.target.value })}
                          />
                          <Input
                            type="number"
                            placeholder="Price"
                            className="w-24"
                            value={addon.price}
                            onChange={(e) => updateAddon(i, { price: parseFloat(e.target.value) || 0 })}
                          />
                          <button type="button" onClick={() => removeAddon(i)} className="p-2 text-red-500 hover:bg-red-50 rounded-md">
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="space-y-6">
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold uppercase tracking-wider text-gray-400">Media</h3>
                    <div className="relative aspect-video w-full overflow-hidden rounded-xl border bg-gray-50">
                      {formData.image_url ? (
                        <Image src={formData.image_url} alt="Product" fill className="object-contain p-4" />
                      ) : (
                        <div className="flex h-full w-full items-center justify-center text-xs text-muted-foreground">No Image</div>
                      )}
                    </div>
                    <Label
                      htmlFor="image-upload"
                      className="flex cursor-pointer items-center justify-center gap-2 rounded-xl border border-dashed py-4 text-sm font-medium hover:bg-gray-50 transition-colors"
                    >
                      <Upload className="h-4 w-4" />
                      {uploading ? "Uploading..." : "Upload High-Quality Image"}
                      <input id="image-upload" type="file" className="hidden" accept="image/*" onChange={handleImageUpload} />
                    </Label>
                    <div className="space-y-2">
                      <Label>PDF Image Layout</Label>
                      <Select
                        value={formData.image_format || 'wide'}
                        onValueChange={(v: 'wide' | 'tall') => setFormData({ ...formData, image_format: v })}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select Layout" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="wide">Format 1 - Wide (Image below description)</SelectItem>
                          <SelectItem value="tall">Format 2 - Tall (Image beside features)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold uppercase tracking-wider text-gray-400">Technical Specs</h3>
                      <button type="button" onClick={addSpec} className="text-xs font-bold text-black hover:underline flex items-center gap-1">
                        <Plus className="h-3 w-3" /> Add
                      </button>
                    </div>
                    <div className="space-y-2">
                      {formData.specs?.map((spec, i) => (
                        <div key={i} className="flex gap-2 items-start">
                          <Input
                            placeholder="Label (e.g. Material)"
                            className="flex-1"
                            value={spec.key}
                            onChange={(e) => updateSpec(i, { key: e.target.value })}
                          />
                          <Input
                            placeholder="Value"
                            className="flex-1"
                            value={spec.value}
                            onChange={(e) => updateSpec(i, { value: e.target.value })}
                          />
                          <button type="button" onClick={() => removeSpec(i)} className="p-2 text-red-500 hover:bg-red-50 rounded-md">
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold uppercase tracking-wider text-gray-400">Product Features</h3>
                      <button type="button" onClick={addFeature} className="text-xs font-bold text-black hover:underline flex items-center gap-1">
                        <Plus className="h-3 w-3" /> Add
                      </button>
                    </div>
                    <div className="space-y-2">
                      {formData.features?.map((feature, i) => (
                        <div key={i} className="flex gap-2 items-start">
                          <Input
                            placeholder="Feature description (e.g., Microprocessor based design)"
                            className="flex-1"
                            value={feature}
                            onChange={(e) => updateFeature(i, e.target.value)}
                          />
                          <button type="button" onClick={() => removeFeature(i)} className="p-2 text-red-500 hover:bg-red-50 rounded-md">
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <DialogFooter className="mt-8 border-t pt-6">
                <button
                  type="submit"
                  className="rounded-xl bg-black px-10 py-3 text-sm font-bold text-white shadow-xl shadow-black/20 transition-all hover:bg-black/90 active:scale-95"
                >
                  {selectedProduct ? "Update Product" : "Create Product"}
                </button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search products by name or category..."
            className="pl-9 h-11"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className="rounded-2xl border bg-white shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-gray-50/50 hover:bg-gray-50/50">
                <TableHead className="w-20 px-6 whitespace-nowrap">Image</TableHead>
                <TableHead className="whitespace-nowrap">Details</TableHead>
                <TableHead className="whitespace-nowrap">Category</TableHead>
                <TableHead className="whitespace-nowrap">Price</TableHead>
                <TableHead className="whitespace-nowrap">Status</TableHead>
                <TableHead className="text-right px-6 whitespace-nowrap">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow><TableCell colSpan={6} className="h-48 text-center font-medium text-gray-400">Fetching products...</TableCell></TableRow>
              ) : filteredProducts.length === 0 ? (
                <TableRow><TableCell colSpan={6} className="h-48 text-center font-medium text-gray-400">No products found.</TableCell></TableRow>
              ) : (
                filteredProducts.map((p) => (
                  <TableRow key={p.id} className="group hover:bg-gray-50/30 transition-colors">
                    <TableCell className="px-6 py-4">
                      <div className="relative h-14 w-14 overflow-hidden rounded-xl border bg-white p-1">
                        {p.image_url ? (
                          <Image src={p.image_url} alt={p.name} fill className="object-contain" />
                        ) : (
                          <div className="flex h-full w-full items-center justify-center text-[10px] font-bold text-gray-300">N/A</div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-0.5">
                        <div className="font-black text-black uppercase tracking-tight">{p.name}</div>
                        <div className="max-w-[240px] truncate text-xs text-gray-400">{p.description}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="bg-gray-100 text-gray-600 border-none font-bold uppercase text-[10px]">{p.category || "Uncategorized"}</Badge>
                    </TableCell>
                    <TableCell className="font-black text-black">₹{p.price.toLocaleString()}</TableCell>
                    <TableCell>
                      <Badge variant={p.active ? "default" : "destructive"} className={p.active ? "bg-black text-white" : ""}>
                        {p.active ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right px-6">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => {
                            setSelectedProduct(p)
                            setFormData({
                              ...p,
                              addons: p.addons || [],
                              specs: p.specs || [],
                            })
                            setIsDialogOpen(true)
                          }}
                          className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                        >
                          <Edit2 className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleToggleStatus(p)}
                          className={`p-2 rounded-lg transition-colors ${p.active ? "text-red-500 hover:bg-red-50" : "text-green-500 hover:bg-green-50"}`}
                        >
                          {p.active ? <PowerOff className="h-4 w-4" /> : <Power className="h-4 w-4" />}
                        </button>
                        <button
                          onClick={() => handleDelete(p.id)}
                          className="p-2 text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
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
