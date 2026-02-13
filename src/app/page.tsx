import { createClient } from '@/lib/supabase/server'
import { redirect } from 'next/navigation'
import QuotationBuilder from '@/components/quotation/QuotationBuilder'

export const dynamic = "force-dynamic"
export const revalidate = 0

export default async function SalesPage() {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()

  if (!user) {
    redirect('/auth/login')
  }

  // Fetch initial data in parallel with optimized queries
  const [productsResponse, settingsResponse, profileResponse] = await Promise.all([
    supabase
      .from('products')
      .select('id, name, description, price, image_url, sku, specs, features, category, addons, image_format')
      .eq('active', true)
      .order('name'),
    supabase
      .from('settings')
      .select('id, company_name, company_logo, company_address, company_phone, company_email, tax_rate, currency_symbol')
      .eq('id', 1)
      .single(),
    supabase
      .from('profiles')
      .select('id, full_name, email, role, active, phone')
      .eq('id', user.id)
      .single()
  ])

  // Role-check and redirect for admin
  if (profileResponse.data?.role === 'admin') {
    redirect('/admin/quotations')
  }

  return (
    <div className="min-h-screen bg-gray-50/50">
      <QuotationBuilder
        initialProducts={productsResponse.data || []}
        settings={settingsResponse.data}
        user={profileResponse.data}
      />
    </div>
  )
}
