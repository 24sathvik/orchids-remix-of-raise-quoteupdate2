import { createClient } from '@/lib/supabase/server'
import { createAdminClient } from '@/lib/supabase/admin'
import { revalidatePath } from 'next/cache'

export async function createSalesperson(formData: FormData) {
  try {
    const email = formData.get('email') as string
    const password = formData.get('password') as string
    const name = formData.get('name') as string

    if (!email || !password || !name) {
      return { error: 'Missing required fields' }
    }

    const supabaseAdmin = createAdminClient()

    // 0. Check if user already exists in profiles to give a clear error
    const { data: existingProfile } = await supabaseAdmin
      .from('profiles')
      .select('id')
      .eq('email', email)
      .single()

    if (existingProfile) {
      return { error: 'A user with this email already exists.' }
    }

    // 1. Create auth user
    const { data: authUser, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { name }
    })

    if (authError) {
      console.error("Auth Create Error:", authError)
      return { error: authError.message }
    }

    if (!authUser?.user) {
      return { error: 'Failed to create user account.' }
    }

    // 2. Create profile
    const { error: profileError } = await supabaseAdmin
      .from('profiles')
      .insert({
        id: authUser.user.id,
        name,
        email, // Ensure email is saved to profile as well if schema requires it
        role: 'sales',
        active: true
      })

    if (profileError) {
      console.error("Profile Create Error:", profileError)
      // Cleanup auth user if profile creation fails? 
      // ideally yes, but for now let's just return error.
      return { error: profileError.message }
    }

    revalidatePath('/admin/users')
    return { success: true }
  } catch (err: any) {
    console.error("Unexpected Error:", err)
    return { error: err.message || 'An unexpected error occurred' }
  }
}

export async function toggleUserStatus(userId: string, active: boolean) {
  const supabaseAdmin = createAdminClient()

  const { error } = await supabaseAdmin
    .from('profiles')
    .update({ active })
    .eq('id', userId)

  if (error) return { error: error.message }

  revalidatePath('/admin/users')
  return { success: true }
}

export async function resetUserPassword(userId: string, newPassword: string) {
  const supabaseAdmin = createAdminClient()

  const { error } = await supabaseAdmin.auth.admin.updateUserById(userId, {
    password: newPassword
  })

  if (error) return { error: error.message }

  return { success: true }
}
