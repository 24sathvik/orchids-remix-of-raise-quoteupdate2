import { createClient } from '@/lib/supabase/server'
import { revalidatePath } from 'next/cache'

export async function upsertProduct(formData: FormData) {
  const supabase = await createClient()

  const id = formData.get('id') as string
  const name = formData.get('name') as string
  const description = formData.get('description') as string
  const price = parseFloat(formData.get('price') as string)
  const tax_percent = parseFloat(formData.get('tax_percent') as string)
  const active = formData.get('active') === 'true'
  const image_format = formData.get('image_format') as string || 'wide'
  const imageFile = formData.get('image') as File | null

  let image_url = formData.get('existing_image_url') as string

  if (imageFile && imageFile.size > 0) {
    const fileExt = imageFile.name.split('.').pop()
    const fileName = `${Math.random()}.${fileExt}`
    const filePath = `product-images/${fileName}`

    const { error: uploadError } = await supabase.storage
      .from('products')
      .upload(filePath, imageFile)

    if (uploadError) return { error: uploadError.message }

    const { data: { publicUrl } } = supabase.storage
      .from('products')
      .getPublicUrl(filePath)

    image_url = publicUrl
  }

  const productData = {
    name,
    description,
    price,
    tax_percent,
    active,
    image_url,
    image_format
  }

  if (id) {
    const { error } = await supabase
      .from('products')
      .update(productData)
      .eq('id', id)

    if (error) return { error: error.message }
  } else {
    const { error } = await supabase
      .from('products')
      .insert(productData)

    if (error) return { error: error.message }
  }

  revalidatePath('/admin/products')
  return { success: true }
}

export async function deleteProduct(id: string) {
  const supabase = await createClient()

  const { error } = await supabase
    .from('products')
    .delete()
    .eq('id', id)

  if (error) return { error: error.message }

  revalidatePath('/admin/products')
  return { success: true }
}

export async function toggleProductStatus(id: string, active: boolean) {
  const supabase = await createClient()

  const { error } = await supabase
    .from('products')
    .update({ active })
    .eq('id', id)

  if (error) return { error: error.message }

  revalidatePath('/admin/products')
  return { success: true }
}
