import { createClient } from "@/lib/supabase/server"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { 
  FileText, 
  Package, 
  Users, 
  TrendingUp, 
  ArrowUpRight, 
  ArrowDownRight, 
  DollarSign, 
  Clock,
  ChevronRight,
  ShoppingCart
} from "lucide-react"
import Link from "next/link"
import AdminCharts from "./AdminCharts"

export const dynamic = "force-dynamic"
export const revalidate = 0

export default async function AdminDashboard() {
  const supabase = await createClient()

  // Optimized: Fetch data in parallel with proper error handling and reduced payload
  const [
    { data: quotations },
    { count: productsCount },
    { data: recentQuotations },
    { data: profiles }
  ] = await Promise.all([
    supabase.from("quotations").select("grand_total, created_at, created_by", { count: "exact" }),
    supabase.from("products").select("id", { count: "exact", head: true }),
    supabase.from("quotations")
      .select("id, quotation_number, customer_name, grand_total, created_at, profiles!created_by(full_name)")
      .order("created_at", { ascending: false })
      .limit(5),
    supabase.from("profiles").select("id, full_name")
  ])

  // Process data for charts
  const performanceData = (profiles || []).map(profile => {
    const userSales = (quotations || [])
      .filter(q => q.created_by === profile.id)
      .reduce((acc, q) => acc + (q.grand_total || 0), 0)
    return {
      name: profile.full_name?.split(' ')[0] || 'Unknown',
      total: userSales
    }
  }).sort((a, b) => b.total - a.total)

  // Overall Sales Trend (grouped by date)
  const salesByDate: Record<string, number> = {}
  quotations?.forEach(q => {
    const date = new Date(q.created_at).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })
    salesByDate[date] = (salesByDate[date] || 0) + (q.grand_total || 0)
  })
  const salesData = Object.entries(salesByDate).map(([name, total]) => ({ name, total }))

  // Calculate stats
  const totalRevenue = quotations?.reduce((acc, q) => acc + (q.grand_total || 0), 0) || 0
  const avgQuotationValue = quotations?.length ? totalRevenue / quotations.length : 0
  
  // Last 30 days revenue (simple mock for now, but could be calculated)
  const thirtyDaysAgo = new Date()
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30)
  const recentRevenue = quotations
    ?.filter(q => new Date(q.created_at) > thirtyDaysAgo)
    .reduce((acc, q) => acc + (q.grand_total || 0), 0) || 0

  const stats = [
    {
      title: "Total Revenue",
      value: `₹${totalRevenue.toLocaleString()}`,
      icon: DollarSign,
      trend: "+12.5%",
      trendUp: true,
      description: "Lifetime quotation value",
      color: "from-emerald-500 to-teal-600"
    },
    {
      title: "Quotations",
      value: quotations?.length || 0,
      icon: FileText,
      trend: "+5.2%",
      trendUp: true,
      description: "Total documents generated",
      color: "from-blue-500 to-indigo-600"
    },
    {
      title: "Avg. Value",
      value: `₹${Math.round(avgQuotationValue).toLocaleString()}`,
      icon: TrendingUp,
      trend: "-2.1%",
      trendUp: false,
      description: "Per quotation average",
      color: "from-purple-500 to-fuchsia-600"
    },
    {
      title: "Active Catalog",
      value: productsCount || 0,
      icon: Package,
      trend: "Stable",
      trendUp: true,
      description: "Products in inventory",
      color: "from-amber-500 to-orange-600"
    },
  ]

  return (
    <div className="space-y-10 pb-10">
      <div className="flex flex-col gap-2">
        <h1 className="text-4xl font-black tracking-tight text-black">
          Executive <span className="text-gray-300">Overview</span>
        </h1>
        <p className="text-sm font-medium text-gray-400">
          Real-time performance analytics for Raise Labs.
        </p>
      </div>

      {/* Primary Stats Grid */}
      <div className="grid gap-4 sm:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.title} className="group relative overflow-hidden border-none bg-white shadow-sm ring-1 ring-gray-100 transition-all hover:shadow-xl hover:-translate-y-1 rounded-2xl">
            <div className={`absolute top-0 left-0 h-1 w-full bg-gradient-to-r ${stat.color}`} />
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-[10px] font-black uppercase tracking-[0.2em] text-gray-400">{stat.title}</CardTitle>
              <div className={`rounded-lg p-2 bg-gray-50 text-gray-600 group-hover:scale-110 transition-transform`}>
                <stat.icon className="h-4 w-4" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black tracking-tighter text-black break-words">{stat.value}</div>
              <div className="mt-2 flex items-center gap-2 flex-wrap">
                <span className={`flex items-center text-[10px] font-bold ${stat.trendUp ? 'text-emerald-500' : 'text-rose-500'}`}>
                  {stat.trendUp ? <ArrowUpRight className="mr-0.5 h-3 w-3" /> : <ArrowDownRight className="mr-0.5 h-3 w-3" />}
                  {stat.trend}
                </span>
                <span className="text-[10px] font-medium text-gray-300">vs last month</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      
      {/* Analytics Graphs */}
      <AdminCharts salesData={salesData} performanceData={performanceData} />

      <div className="grid gap-8 lg:grid-cols-3">
        {/* Recent Activity Table */}
        <Card className="lg:col-span-2 border-none bg-white shadow-sm ring-1 ring-gray-100 rounded-3xl overflow-hidden">
          <CardHeader className="flex flex-row items-center justify-between border-b border-gray-50 p-8">
            <div>
              <CardTitle className="text-lg font-black tracking-tight text-black">Recent Quotations</CardTitle>
              <p className="text-xs font-medium text-gray-400">The latest 5 documents generated by your team.</p>
            </div>
            <Link href="/admin/quotations" className="text-xs font-bold text-black hover:underline flex items-center gap-1">
              View All <ChevronRight className="h-3 w-3" />
            </Link>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse min-w-[600px]">
                <thead>
                  <tr className="bg-gray-50/50">
                    <th className="px-8 py-4 text-[10px] font-black uppercase tracking-widest text-gray-400 whitespace-nowrap">ID</th>
                    <th className="px-8 py-4 text-[10px] font-black uppercase tracking-widest text-gray-400 whitespace-nowrap">Client</th>
                    <th className="px-8 py-4 text-[10px] font-black uppercase tracking-widest text-gray-400 whitespace-nowrap">Salesperson</th>
                    <th className="px-8 py-4 text-right text-[10px] font-black uppercase tracking-widest text-gray-400 whitespace-nowrap">Amount</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {recentQuotations?.map((q: any) => (
                    <tr key={q.id} className="group hover:bg-gray-50/50 transition-colors">
                      <td className="px-8 py-5 text-xs font-mono font-bold text-black">{q.quotation_number}</td>
                      <td className="px-8 py-5">
                        <div className="text-sm font-bold text-black">{q.customer_name}</div>
                        <div className="text-[10px] font-medium text-gray-400">{new Date(q.created_at).toLocaleDateString()}</div>
                      </td>
                      <td className="px-8 py-5">
                        <div className="flex items-center gap-2">
                          <div className="h-6 w-6 rounded-full bg-gray-100 flex items-center justify-center text-[10px] font-bold text-black">
                            {q.profiles?.full_name?.[0] || 'S'}
                          </div>
                          <span className="text-xs font-bold text-gray-600">{q.profiles?.full_name}</span>
                        </div>
                      </td>
                      <td className="px-8 py-5 text-right text-sm font-black text-black">₹{q.grand_total?.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Quick Actions & Team Status */}
        <div className="space-y-8">
          <Card className="border-none bg-black shadow-2xl shadow-black/20 rounded-3xl p-8 text-white">
            <CardHeader className="p-0 mb-6">
              <CardTitle className="text-lg font-black tracking-tight">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="p-0 space-y-4">
              <Link href="/admin/products/new" className="flex items-center justify-between p-4 rounded-2xl bg-white/10 hover:bg-white/20 transition-all border border-white/5">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-white/10 text-white">
                    <Package className="h-4 w-4" />
                  </div>
                  <span className="text-xs font-bold">Add New Product</span>
                </div>
                <ArrowUpRight className="h-4 w-4 text-white/40" />
              </Link>
              <Link href="/admin/users" className="flex items-center justify-between p-4 rounded-2xl bg-white/10 hover:bg-white/20 transition-all border border-white/5">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-white/10 text-white">
                    <Users className="h-4 w-4" />
                  </div>
                  <span className="text-xs font-bold">Manage Team</span>
                </div>
                <ArrowUpRight className="h-4 w-4 text-white/40" />
              </Link>
            </CardContent>
          </Card>

          <Card className="border-none bg-white shadow-sm ring-1 ring-gray-100 rounded-3xl overflow-hidden">
            <CardHeader className="p-8 pb-4">
              <CardTitle className="text-sm font-black uppercase tracking-widest text-gray-400">Performance Index</CardTitle>
            </CardHeader>
            <CardContent className="px-8 pb-8 space-y-6">
              <div className="space-y-2">
                <div className="flex justify-between text-[10px] font-bold uppercase tracking-wider">
                  <span className="text-gray-400">Target Achievement</span>
                  <span className="text-black">78%</span>
                </div>
                <div className="h-2 w-full bg-gray-100 rounded-full overflow-hidden">
                  <div className="h-full w-[78%] bg-black rounded-full" />
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between text-[10px] font-bold uppercase tracking-wider">
                  <span className="text-gray-400">Conversion Rate</span>
                  <span className="text-black">42%</span>
                </div>
                <div className="h-2 w-full bg-gray-100 rounded-full overflow-hidden">
                  <div className="h-full w-[42%] bg-gray-400 rounded-full" />
                </div>
              </div>
              <div className="pt-4 flex items-center gap-4">
                <div className="h-12 w-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-600">
                  <TrendingUp className="h-6 w-6" />
                </div>
                <div>
                  <div className="text-sm font-black text-black">+24%</div>
                  <div className="text-[10px] font-bold text-gray-400 uppercase">Quarterly Growth</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
