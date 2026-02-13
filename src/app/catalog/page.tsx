import { createClient } from '@/lib/supabase/server'
import { redirect } from 'next/navigation'
import Image from 'next/image'
import { Search, Package, Layers } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'

export const dynamic = "force-dynamic"
export const revalidate = 0

export default async function CatalogPage() {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()

  if (!user) {
    redirect('/auth/login')
  }

  const { data: products } = await supabase
    .from('products')
    .select('id, name, description, price, image_url, sku, specs, category, active')
    .eq('active', true)
    .order('name')

  return (
    <div className="min-h-screen bg-gray-50/50 p-8">
      <div className="mx-auto max-w-6xl space-y-8">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-black">Product Catalog</h1>
          <p className="text-sm font-medium text-gray-400">View detailed pharmaceutical engineering specifications.</p>
        </div>

        <div className="relative">
          <Search className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <Input 
            placeholder="Search products, SKUs, or categories..." 
            className="h-12 rounded-xl border-none bg-white pl-11 shadow-sm ring-1 ring-gray-100 focus:ring-black transition-all"
          />
        </div>

        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {products?.map((product) => (
            <Card key={product.id} className="group overflow-hidden border-none bg-white shadow-sm ring-1 ring-gray-100 rounded-2xl transition-all hover:shadow-xl hover:shadow-black/5">
              <div className="relative h-48 w-full bg-gray-50/50">
                {product.image_url ? (
                  <Image 
                    src={product.image_url} 
                    alt={product.name} 
                    fill 
                    className="object-contain p-6 transition-transform group-hover:scale-105" 
                  />
                ) : (
                  <div className="flex h-full items-center justify-center text-gray-200">
                    <Package className="h-12 w-12" />
                  </div>
                )}
                <div className="absolute top-4 left-4">
                  <Badge className="bg-white/80 backdrop-blur-md text-black border-none font-bold text-[10px] uppercase tracking-wider px-3 py-1">
                    {product.category || 'General'}
                  </Badge>
                </div>
              </div>
              <CardHeader className="p-6 pb-2">
                <div className="flex justify-between items-start">
                  <CardTitle className="text-lg font-black tracking-tight text-black uppercase">{product.name}</CardTitle>
                </div>
                <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">{product.sku}</p>
              </CardHeader>
              <CardContent className="p-6 pt-0 space-y-4">
                <p className="text-sm text-gray-500 line-clamp-2 leading-relaxed">{product.description}</p>
                <div className="flex items-center justify-between">
                  <span className="text-xl font-black tracking-tighter text-black">₹{product.price.toLocaleString()}</span>
                </div>
                {product.specs && (
                  <div className="pt-4 border-t border-gray-50 grid grid-cols-2 gap-2">
                    {(product.specs as any[]).slice(0, 2).map((spec, i) => (
                      <div key={i} className="space-y-0.5">
                        <p className="text-[8px] font-black text-gray-400 uppercase tracking-widest">{spec.key}</p>
                        <p className="text-[10px] font-bold text-black truncate">{spec.value}</p>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  )
}
