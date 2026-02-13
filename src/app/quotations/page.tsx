import { createClient } from '@/lib/supabase/server'
import { redirect } from 'next/navigation'
import QuotationsList from '@/components/quotation/QuotationsList'

export const dynamic = "force-dynamic"
export const revalidate = 0

export default async function SalesQuotationsPage() {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()

  if (!user) {
    redirect('/auth/login')
  }

  const { data: profile } = await supabase
    .from('profiles')
    .select('role, full_name')
    .eq('id', user.id)
    .single()

    return (
      <div className="min-h-screen bg-gray-50/50">
        <div className="mx-auto max-w-6xl p-8">
          <QuotationsList user={profile} userId={user.id} />
        </div>
      </div>
    )

}
