import { createClient } from '@supabase/supabase-js'
import { createServerClient } from '@supabase/ssr'
import { NextResponse } from 'next/server'
import { cookies } from 'next/headers'

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

function getAdminClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    }
  )
}

async function getAuthenticatedAdmin() {
  const cookieStore = await cookies()

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll()
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options)
            )
          } catch {
            // Called from a Server Component / Route Handler after headers sent
          }
        },
      },
    }
  )

  const { data: { user }, error } = await supabase.auth.getUser()

  if (error || !user) {
    return null
  }

  const supabaseAdmin = getAdminClient()

  // Check admin role using admin client (bypasses RLS)
  const { data: profile } = await supabaseAdmin
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single()

  if (profile?.role !== 'admin') {
    return null
  }

  return { user, profile, supabaseAdmin }
}

export async function GET() {
  const auth = await getAuthenticatedAdmin()
  if (!auth) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { data: users, error } = await auth.supabaseAdmin
    .from('profiles')
    .select('id, name:full_name, email, role, active, created_at, phone')
    .order('created_at', { ascending: false })

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 400 })
  }

  return NextResponse.json(users)
}

export async function POST(request: Request) {
  try {
    const auth = await getAuthenticatedAdmin()
    if (!auth) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const { email, password, name, role, phone } = body

    const supabaseAdmin = auth.supabaseAdmin

    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: name, role, phone }
    })

    if (authError) {
      return NextResponse.json({ error: authError.message }, { status: 400 })
    }

    const { error: profileError } = await supabaseAdmin
      .from('profiles')
      .insert({
        id: authData.user.id,
        full_name: name,
        email,
        role,
        phone,
        active: true
      })

  if (profileError) {
    return NextResponse.json({ error: profileError.message }, { status: 400 })
  }

  return NextResponse.json({ success: true })
  } catch (error: any) {
    console.error('POST /api/admin/users error:', error)
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 })
  }
}

export async function PATCH(request: Request) {
  try {
    const auth = await getAuthenticatedAdmin()
    if (!auth) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const { id, active, password, name, role, phone } = body

    const supabaseAdmin = auth.supabaseAdmin

  if (password) {
    const { error: authError } = await supabaseAdmin.auth.admin.updateUserById(id, {
      password
    })
    if (authError) return NextResponse.json({ error: authError.message }, { status: 400 })
  }

  if (active !== undefined || name !== undefined || role !== undefined || phone !== undefined) {
    const updateData: any = {}
    if (active !== undefined) updateData.active = active
    if (name !== undefined) updateData.full_name = name
    if (role !== undefined) updateData.role = role
    if (phone !== undefined) updateData.phone = phone

    const { error: profileError } = await supabaseAdmin
      .from('profiles')
      .update(updateData)
      .eq('id', id)
    
    if (profileError) return NextResponse.json({ error: profileError.message }, { status: 400 })
  }

  return NextResponse.json({ success: true })
  } catch (error: any) {
    console.error('PATCH /api/admin/users error:', error)
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 })
  }
}

export async function DELETE(request: Request) {
  try {
    const auth = await getAuthenticatedAdmin()
    if (!auth) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const id = searchParams.get('id')

    if (!id) {
      return NextResponse.json({ error: 'Missing ID' }, { status: 400 })
    }

    const supabaseAdmin = auth.supabaseAdmin

  const { error: authError } = await supabaseAdmin.auth.admin.deleteUser(id)
  if (authError) return NextResponse.json({ error: authError.message }, { status: 400 })

  const { error: profileError } = await supabaseAdmin
    .from('profiles')
    .delete()
    .eq('id', id)

  if (profileError) return NextResponse.json({ error: profileError.message }, { status: 400 })

  return NextResponse.json({ success: true })
  } catch (error: any) {
    console.error('DELETE /api/admin/users error:', error)
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 })
  }
}
