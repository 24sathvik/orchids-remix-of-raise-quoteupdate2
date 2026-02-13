import { createClient } from '@/lib/supabase/server'
import { revalidatePath } from 'next/cache'

export async function updateSettings(formData: FormData) {
  const supabase = await createClient()
  
  const company_name = formData.get('company_name') as string
  const address = formData.get('address') as string
  const phone = formData.get('phone') as string
  const email = formData.get('email') as string
  const gst_number = formData.get('gst_number') as string
  const currency_symbol = formData.get('currency_symbol') as string
  const default_tax_percent = parseFloat(formData.get('default_tax_percent') as string)
  const terms_text = formData.get('terms_text') as string
  const signature_name = formData.get('signature_name') as string
  const signature_role = formData.get('signature_role') as string
  const logoFile = formData.get('logo') as File | null

  let company_logo = formData.get('existing_logo_url') as string

  if (logoFile && logoFile.size > 0) {
    const fileExt = logoFile.name.split('.').pop()
    const fileName = `logo.${fileExt}`
    const filePath = `company-logos/${fileName}`

    const { error: uploadError } = await supabase.storage
      .from('logos')
      .upload(filePath, logoFile, { upsert: true })

    if (uploadError) return { error: uploadError.message }

    const { data: { publicUrl } } = supabase.storage
      .from('logos')
      .getPublicUrl(filePath)
    
    company_logo = publicUrl
  }

  const { error } = await supabase
    .from('settings')
    .update({
      company_name,
      address,
      phone,
      email,
      gst_number,
      currency_symbol,
      default_tax_percent,
      terms_text,
      signature_name,
      signature_role,
      company_logo,
      updated_at: new Date().toISOString()
    })
    .eq('id', 1)

  if (error) return { error: error.message }

  revalidatePath('/admin/settings')
  return { success: true }
}
