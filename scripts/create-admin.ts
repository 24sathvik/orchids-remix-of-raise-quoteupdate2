import { createClient } from '@supabase/supabase-js'

const supabaseUrl = 'https://qbbzmusbktszfyycgcbw.supabase.co'
const supabaseServiceKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFiYnptdXNia3RzemZ5eWNnY2J3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2OTA3NDQ4NywiZXhwIjoyMDg0NjUwNDg3fQ._iEHeY-KAPXz6uMGWrn43ggBM07kLZRMMCz-LibNkL4'

const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
})

async function createAdmin() {
  const email = 'admin@gamil.com'
  const password = 'RaiseLabs@123'
  const name = 'Admin'

  console.log('Creating admin user...')
  
  const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { name, role: 'admin' }
  })

  if (authError) {
    console.error('Auth error:', authError.message)
    process.exit(1)
  }

  console.log('User created in auth. Creating profile...')

  const { error: profileError } = await supabaseAdmin
    .from('profiles')
    .insert({
      id: authData.user.id,
      name,
      role: 'admin',
      active: true
    })

  if (profileError) {
    console.error('Profile error:', profileError.message)
    process.exit(1)
  }

  console.log('Admin user created successfully!')
}

createAdmin()
