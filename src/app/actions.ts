'use server'

import { createClient } from '@/lib/supabase/server'
import { revalidatePath } from 'next/cache'

export async function saveQuotation(data: any) {
  const supabase = await createClient()
  
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return { error: 'Unauthorized' }

  // Get the last quotation number for sequential numbering
  const { data: lastQuotation } = await supabase
    .from('quotations')
    .select('quotation_number')
    .order('created_at', { ascending: false })
    .limit(1)
    .single()

  let quotationNumber = data.quotation_number
  if (lastQuotation?.quotation_number) {
    // Extract number from format like "RLE-107" and increment
    const match = lastQuotation.quotation_number.match(/RLE-(\d+)/)
    if (match) {
      const nextNumber = parseInt(match[1]) + 1
      quotationNumber = `RLE-${nextNumber}`
    }
  } else {
    // First quotation
    quotationNumber = 'RLE-101'
  }

  const { error } = await supabase
    .from('quotations')
    .insert({
      quotation_number: quotationNumber,
      created_by: user.id,
      customer_name: data.customer_name,
      customer_phone: data.customer_phone,
      customer_email: data.customer_email,
      customer_address: data.customer_address,
      items_json: data.items,
      subtotal: data.subtotal,
      tax_total: data.tax_total,
      discount_total: data.discount_total,
      grand_total: data.grand_total,
      pdf_url: data.pdf_url,
    })

  if (error) {
    console.error('Error saving quotation:', error)
    return { error: error.message }
  }

  revalidatePath('/admin/quotations')
  return { success: true, quotationNumber }
}

export async function uploadQuotationPDF(fileName: string, blob: Blob) {
  const supabase = await createClient()
  
  const filePath = `quotations/${fileName}`
  
  const { error: uploadError } = await supabase.storage
    .from('quotations_docs') // I need to create this bucket
    .upload(filePath, blob, { contentType: 'application/pdf' })

  if (uploadError) return { error: uploadError.message }

  const { data: { publicUrl } } = supabase.storage
    .from('quotations_docs')
    .getPublicUrl(filePath)
  
  return { publicUrl }
}
