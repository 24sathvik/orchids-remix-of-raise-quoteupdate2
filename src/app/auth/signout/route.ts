import { createClient } from '@/lib/supabase/server'
import { revalidatePath } from 'next/cache'
import { type NextRequest, NextResponse } from 'next/server'

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(req: NextRequest) {
  const supabase = await createClient()

  // Check if a user's logged in
  const {
    data: { user },
  } = await supabase.auth.getUser()

  if (user) {
    await supabase.auth.signOut()
  }

  const response = NextResponse.redirect(new URL('/auth/login', req.url), {
    status: 302,
  })

  // Ensure all cookies are cleared
  response.cookies.delete('sb-qbbzmusbktszfyycgcbw-auth-token')
  response.cookies.delete('sb-access-token')
  response.cookies.delete('sb-refresh-token')

  revalidatePath('/', 'layout')
  return response
}

export async function POST(req: NextRequest) {
  return GET(req)
}
