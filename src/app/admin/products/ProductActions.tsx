'use client'

import { useState } from 'react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Button } from '@/components/ui/button'
import { MoreHorizontal, Power, PowerOff, Trash2 } from 'lucide-react'
import { toggleProductStatus, deleteProduct } from './actions'
import { toast } from 'sonner'
import ProductDialog from './ProductDialog'

export default function ProductActions({ product }: { product: any }) {
  const [isLoading, setIsLoading] = useState(false)

  async function handleToggleStatus() {
    setIsLoading(true)
    const result = await toggleProductStatus(product.id, !product.active)
    setIsLoading(false)

    if (result.error) {
      toast.error(result.error)
    } else {
      toast.success(`Product ${product.active ? 'deactivated' : 'activated'} successfully`)
    }
  }

  async function handleDelete() {
    if (!confirm('Are you sure you want to delete this product?')) return

    setIsLoading(true)
    const result = await deleteProduct(product.id)
    setIsLoading(false)

    if (result.error) {
      toast.error(result.error)
    } else {
      toast.success('Product deleted successfully')
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="h-8 w-8 p-0">
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-[200px]">
        <DropdownMenuLabel>Actions</DropdownMenuLabel>
        <DropdownMenuSeparator />
        
        <ProductDialog product={product} />
        
        <DropdownMenuItem 
          onClick={handleToggleStatus} 
          className={`gap-2 cursor-pointer ${product.active ? 'text-orange-600 focus:text-orange-600' : 'text-emerald-600 focus:text-emerald-600'}`}
        >
          {product.active ? (
            <>
              <PowerOff className="h-4 w-4" />
              Deactivate Product
            </>
          ) : (
            <>
              <Power className="h-4 w-4" />
              Activate Product
            </>
          )}
        </DropdownMenuItem>
        
        <DropdownMenuSeparator />
        
        <DropdownMenuItem 
          onClick={handleDelete} 
          className="gap-2 cursor-pointer text-red-600 focus:text-red-600"
        >
          <Trash2 className="h-4 w-4" />
          Delete Product
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
