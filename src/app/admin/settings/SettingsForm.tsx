'use client'

import { useState, memo } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { Image as ImageIcon, Loader2, Save } from 'lucide-react'
import { updateSettings } from './actions'
import { toast } from 'sonner'

export default memo(function SettingsForm({ settings }: { settings: any }) {
  const [isLoading, setIsLoading] = useState(false)
  const [previewUrl, setPreviewUrl] = useState<string | null>(settings?.logo_url || null)

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setIsLoading(true)

    const formData = new FormData(e.currentTarget)
    if (settings?.logo_url) formData.append('existing_logo_url', settings.logo_url)

    const result = await updateSettings(formData)

    setIsLoading(false)

    if (result.error) {
      toast.error(result.error)
    } else {
      toast.success('Settings updated successfully')
    }
  }

  function handleLogoChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) {
      const url = URL.createObjectURL(file)
      setPreviewUrl(url)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-8">
      <div className="grid gap-6 md:grid-cols-2">
        <Card className="border-none shadow-sm ring-1 ring-gray-200">
          <CardHeader>
            <CardTitle>Business Information</CardTitle>
            <CardDescription>General company details for your quotations.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-6 pb-4">
              <div className="h-20 w-20 rounded border-2 border-dashed flex items-center justify-center bg-gray-50 relative overflow-hidden group">
                {previewUrl ? (
                  <img src={previewUrl} alt="Logo" className="h-full w-full object-contain p-2" />
                ) : (
                  <ImageIcon className="h-6 w-6 text-gray-400" />
                )}
                <div className="absolute inset-0 bg-black/40 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                  <Label htmlFor="logo" className="cursor-pointer text-white text-[10px] font-medium">
                    Change
                  </Label>
                </div>
              </div>
              <div className="flex-1">
                <Label htmlFor="logo" className="text-sm font-medium">Company Logo</Label>
                <Input 
                  id="logo" 
                  name="logo" 
                  type="file" 
                  accept="image/*" 
                  className="mt-1" 
                  onChange={handleLogoChange}
                />
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="company_name">Company Name</Label>
              <Input id="company_name" name="company_name" defaultValue={settings?.company_name} required />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="address">Address</Label>
              <Textarea id="address" name="address" defaultValue={settings?.address} className="min-h-[100px]" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="phone">Phone</Label>
                <Input id="phone" name="phone" defaultValue={settings?.phone} />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="email">Email</Label>
                <Input id="email" name="email" type="email" defaultValue={settings?.email} />
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="gst_number">GST / Tax ID (Optional)</Label>
              <Input id="gst_number" name="gst_number" defaultValue={settings?.gst_number} />
            </div>
          </CardContent>
        </Card>

        <Card className="border-none shadow-sm ring-1 ring-gray-200">
          <CardHeader>
            <CardTitle>Quotation Defaults</CardTitle>
            <CardDescription>Default values for new quotations.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="currency_symbol">Currency Symbol</Label>
                <Input id="currency_symbol" name="currency_symbol" defaultValue={settings?.currency_symbol || '₹'} />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="default_tax_percent">Default Tax %</Label>
                <Input id="default_tax_percent" name="default_tax_percent" type="number" step="0.01" defaultValue={settings?.default_tax_percent || 0} />
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="terms_text">Terms & Conditions</Label>
              <Textarea id="terms_text" name="terms_text" defaultValue={settings?.terms_text} className="min-h-[150px]" />
            </div>
            <div className="grid grid-cols-2 gap-4 pt-2">
              <div className="grid gap-2">
                <Label htmlFor="signature_name">Authorized Signatory Name</Label>
                <Input id="signature_name" name="signature_name" defaultValue={settings?.signature_name} />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="signature_role">Signatory Role</Label>
                <Input id="signature_role" name="signature_role" defaultValue={settings?.signature_role} />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex justify-end">
        <Button 
          type="submit" 
          className="bg-black hover:bg-gray-800 text-white h-12 px-8 shadow-lg"
          disabled={isLoading}
        >
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Saving Changes...
            </>
          ) : (
            <>
              <Save className="mr-2 h-4 w-4" />
              Save Settings
            </>
          )}
        </Button>
      </div>
    </form>
  )
})
