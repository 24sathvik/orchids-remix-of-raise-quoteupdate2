'use client'

import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Plus, Loader2, Image as ImageIcon, LayoutTemplate } from 'lucide-react'
import { upsertProduct } from './actions'
import { toast } from 'sonner'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

interface Product {
  id: string
  name: string
  description: string
  price: number
  tax_percent: number
  image_url: string | null
  active: boolean
  image_format?: 'wide' | 'tall'
}

export default function ProductDialog({ product }: { product?: Product }) {
  const [open, setOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [previewUrl, setPreviewUrl] = useState<string | null>(product?.image_url || null)

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setIsLoading(true)

    const formData = new FormData(e.currentTarget)
    // Ensure ID is passed for updates
    if (product?.id) {
      formData.append('id', product.id)
    }

    // Handle image upload logic carefully
    const imageInput = e.currentTarget.querySelector('input[type="file"]') as HTMLInputElement;
    if (imageInput?.files?.length === 0 && product?.image_url) {
      formData.append('existing_image_url', product.image_url)
    }

    try {
      const result = await upsertProduct(formData)

      if (result?.error) {
        toast.error(result.error)
      } else {
        toast.success(`Product ${product ? 'updated' : 'created'} successfully`)
        setOpen(false)
      }
    } catch (error) {
      console.error("Submit error:", error);
      toast.error("Something went wrong. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }

  function handleImageChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) {
      const url = URL.createObjectURL(file)
      setPreviewUrl(url)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {product ? (
          <Button variant="ghost" size="sm" className="h-8 w-full justify-start px-2 font-medium text-gray-600 hover:text-black hover:bg-gray-50">
            Edit
          </Button>
        ) : (
          <Button className="h-10 gap-2 rounded-xl bg-black px-4 font-bold text-white hover:bg-gray-900 shadow-lg shadow-black/20 transition-all">
            <Plus className="h-4 w-4" />
            Add Product
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="max-w-2xl gap-0 p-0 overflow-hidden rounded-2xl border-none bg-white shadow-2xl">
        <div className="border-b border-gray-100 bg-gray-50/50 p-6">
          <DialogHeader>
            <DialogTitle className="text-xl font-black tracking-tight text-black">
              {product ? 'Edit Product' : 'New Product'}
            </DialogTitle>
            <DialogDescription className="text-sm font-medium text-gray-500">
              {product ? 'Update product details and specifications' : 'Add a new product to your catalog'}
            </DialogDescription>
          </DialogHeader>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col">
          <div className="p-6 space-y-8">
            {/* Image Section */}
            <div className="flex flex-col gap-6 sm:flex-row">
              <div className="flex-shrink-0">
                <Label className="mb-3 block text-xs font-bold uppercase tracking-wider text-gray-400">Product Image</Label>
                <div className="group relative flex h-40 w-40 items-center justify-center overflow-hidden rounded-2xl border-2 border-dashed border-gray-200 bg-gray-50 transition-all hover:border-gray-300">
                  {previewUrl ? (
                    <img src={previewUrl} alt="Preview" className="h-full w-full object-contain p-2" />
                  ) : (
                    <div className="flex flex-col items-center gap-2 text-gray-400">
                      <ImageIcon className="h-8 w-8" />
                      <span className="text-[10px] font-bold uppercase">No Image</span>
                    </div>
                  )}
                  <div className="absolute inset-0 flex items-center justify-center bg-black/60 opacity-0 transition-opacity group-hover:opacity-100">
                    <Label htmlFor="image-upload" className="cursor-pointer rounded-lg bg-white px-3 py-1.5 text-xs font-bold text-black hover:bg-gray-100">
                      Change
                    </Label>
                  </div>
                </div>
                <Input
                  id="image-upload"
                  name="image"
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={handleImageChange}
                />
              </div>

              <div className="flex-1 space-y-6">
                <div className="grid gap-6 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="name" className="text-xs font-bold text-gray-700">Product Name</Label>
                    <Input
                      id="name"
                      name="name"
                      defaultValue={product?.name}
                      placeholder="e.g. Laminar Air Flow"
                      required
                      className="h-10 rounded-xl border-gray-200 bg-gray-50/50 font-medium focus:bg-white focus:ring-0"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="image_format" className="text-xs font-bold text-gray-700">Display Format</Label>
                    <Select name="image_format" defaultValue={product?.image_format || 'wide'}>
                      <SelectTrigger className="h-10 rounded-xl border-gray-200 bg-gray-50/50 font-medium focus:bg-white focus:ring-0">
                        <SelectValue placeholder="Select format" />
                      </SelectTrigger>
                      <SelectContent className="rounded-xl border-gray-100 shadow-xl">
                        <SelectItem value="wide" className="font-medium">Wide (Standard)</SelectItem>
                        <SelectItem value="tall" className="font-medium">Tall (Side-by-side)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description" className="text-xs font-bold text-gray-700">Description</Label>
                  <Textarea
                    id="description"
                    name="description"
                    defaultValue={product?.description}
                    placeholder="Product description..."
                    className="min-h-[80px] rounded-xl border-gray-200 bg-gray-50/50 font-medium focus:bg-white focus:ring-0 resize-none"
                  />
                </div>

                <div className="grid gap-6 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="price" className="text-xs font-bold text-gray-700">Base Price (₹)</Label>
                    <div className="relative">
                      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 font-bold">₹</span>
                      <Input
                        id="price"
                        name="price"
                        type="number"
                        step="0.01"
                        defaultValue={product?.price}
                        placeholder="0.00"
                        required
                        className="h-10 rounded-xl border-gray-200 bg-gray-50/50 pl-7 font-bold focus:bg-white focus:ring-0"
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="specs" className="text-xs font-bold text-gray-700">Status</Label>
                    <div className="flex h-10 items-center gap-3 rounded-xl border border-gray-200 bg-gray-50/50 px-4">
                      <input
                        type="checkbox"
                        id="active"
                        name="active"
                        value="true"
                        defaultChecked={product ? product.active : true}
                        className="h-4 w-4 rounded border-gray-300 text-black focus:ring-black"
                      />
                      <Label htmlFor="active" className="text-sm font-bold text-gray-600 cursor-pointer">Active Product</Label>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="border-t border-gray-100 bg-gray-50/50 p-6 flex justify-end gap-3">
            <Button
              type="button"
              variant="outline"
              onClick={() => setOpen(false)}
              className="h-11 rounded-xl border-gray-200 font-bold text-gray-600 hover:bg-gray-100"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              className="h-11 rounded-xl bg-black px-8 font-bold text-white shadow-lg shadow-black/20 hover:bg-gray-900 transition-all"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : (
                product ? 'Save Changes' : 'Create Product'
              )}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
