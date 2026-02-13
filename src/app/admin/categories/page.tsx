"use client"

import { useEffect, useState } from "react"
import { Plus, Search, Trash2, Edit2, FolderPlus, Layers } from "lucide-react"
import { toast } from "sonner"

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
import { createClient } from "@/lib/supabase/client"

interface Category {
  id: string
  name: string
  created_at: string
}

export default function CategoriesPage() {
  const [categories, setCategories] = useState<Category[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState("")
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [selectedCategory, setSelectedCategory] = useState<Category | null>(null)
  const [name, setName] = useState("")

  const supabase = createClient()

  useEffect(() => {
    fetchCategories()
  }, [])

  const fetchCategories = async () => {
    const { data, error } = await supabase
      .from("categories")
      .select("*")
      .order("name")
    
    if (error) toast.error(error.message)
    else setCategories(data || [])
    setLoading(false)
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (selectedCategory) {
        const { error } = await supabase
          .from("categories")
          .update({ name })
          .eq("id", selectedCategory.id)
        if (error) throw error
        toast.success("Category updated successfully")
      } else {
        const { error } = await supabase
          .from("categories")
          .insert({ name })
        if (error) throw error
        toast.success("Category created successfully")
      }
      setIsDialogOpen(false)
      setName("")
      setSelectedCategory(null)
      fetchCategories()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure? Products in this category will not be deleted but will lose their category association.")) return
    try {
      const { error } = await supabase
        .from("categories")
        .delete()
        .eq("id", id)
      if (error) throw error
      toast.success("Category deleted successfully")
      fetchCategories()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const filtered = categories.filter(c => 
    c.name.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-black">Categories</h1>
          <p className="text-sm font-medium text-gray-400">Organize your product line for faster selection.</p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={(open) => {
          setIsDialogOpen(open)
          if (!open) {
            setName("")
            setSelectedCategory(null)
          }
        }}>
          <DialogTrigger asChild>
            <button className="flex items-center gap-2 rounded-xl bg-black px-6 py-3 text-sm font-bold text-white shadow-xl shadow-black/20 transition-all hover:bg-black/90 active:scale-95">
              <Plus className="h-4 w-4" />
              Add Category
            </button>
          </DialogTrigger>
          <DialogContent className="rounded-2xl sm:max-w-[400px]">
            <form onSubmit={handleSave}>
              <DialogHeader>
                <DialogTitle className="text-xl font-black">{selectedCategory ? "Edit Category" : "New Category"}</DialogTitle>
                <DialogDescription className="font-medium text-gray-400">
                  {selectedCategory ? "Update the name of this category." : "Define a new product category."}
                </DialogDescription>
              </DialogHeader>
              <div className="py-6 space-y-2">
                <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Category Name</Label>
                <Input 
                  required 
                  className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white transition-all"
                  placeholder="e.g. Cleanroom Equipment"
                  value={name} 
                  onChange={(e) => setName(e.target.value)} 
                />
              </div>
              <DialogFooter>
                <button 
                  type="submit" 
                  className="w-full rounded-xl bg-black py-4 text-sm font-bold text-white shadow-xl shadow-black/20 transition-all hover:bg-black/90 active:scale-95"
                >
                  {selectedCategory ? "Update Category" : "Create Category"}
                </button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="relative">
        <Search className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
        <Input
          placeholder="Search categories..."
          className="h-12 rounded-xl border-none bg-white pl-11 shadow-sm ring-1 ring-gray-100 focus:ring-black transition-all"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="overflow-hidden rounded-2xl border-none bg-white shadow-sm ring-1 ring-gray-100">
        <Table>
          <TableHeader>
            <TableRow className="border-gray-50 hover:bg-transparent">
              <TableHead className="h-14 px-6 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Category Name</TableHead>
              <TableHead className="h-14 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Created At</TableHead>
              <TableHead className="h-14 px-6 text-right text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={3} className="h-32 text-center text-sm font-medium text-gray-400">
                  Fetching categories...
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={3} className="h-32 text-center text-sm font-medium text-gray-400">
                  No categories found.
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((cat) => (
                <TableRow key={cat.id} className="border-gray-50 group hover:bg-gray-50/50 transition-colors">
                  <TableCell className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-400 transition-colors group-hover:bg-black group-hover:text-white">
                        <Layers className="h-4 w-4" />
                      </div>
                      <span className="font-bold text-black">{cat.name}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs font-bold text-gray-400 uppercase tracking-tighter">
                    {new Date(cat.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                  </TableCell>
                  <TableCell className="px-6 text-right">
                    <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button 
                        onClick={() => {
                          setSelectedCategory(cat)
                          setName(cat.name)
                          setIsDialogOpen(true)
                        }}
                        className="rounded-lg p-2 text-gray-400 hover:bg-gray-100 hover:text-black transition-all"
                        title="Edit Category"
                      >
                        <Edit2 className="h-4 w-4" />
                      </button>
                      <button 
                        onClick={() => handleDelete(cat.id)}
                        className="rounded-lg p-2 text-gray-400 hover:bg-red-50 hover:text-red-500 transition-all"
                        title="Delete Category"
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
  )
}
