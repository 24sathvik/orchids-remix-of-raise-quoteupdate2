"use client"

import { useEffect, useState } from "react"
import { Save, Upload } from "lucide-react"
import { toast } from "sonner"
import Image from "next/image"

import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { createClient } from "@/lib/supabase/client"

export default function SettingsPage() {
  const [settings, setSettings] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const supabase = createClient()

  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    const { data, error } = await supabase
      .from("settings")
      .select("*")
      .eq("id", 1)
      .single()
    
    if (error) toast.error(error.message)
    else setSettings(data)
    setLoading(false)
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const { error } = await supabase
        .from("settings")
        .update(settings)
        .eq("id", 1)
      
      if (error) throw error
      toast.success("Settings updated successfully")
    } catch (err: any) {
      toast.error(err.message)
    } finally {
      setSaving(false)
    }
  }

  const handleLogoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    try {
      const fileExt = file.name.split(".").pop()
      const fileName = `logo.${fileExt}`
      const filePath = `company-logos/${fileName}`
      
      const { error: uploadError } = await supabase.storage
        .from("logos")
        .upload(filePath, file, { upsert: true })

      if (uploadError) throw uploadError

      const { data: { publicUrl } } = supabase.storage
        .from("logos")
        .getPublicUrl(filePath)

      setSettings({ ...settings, company_logo: publicUrl })
      
      // Save immediately to database
      const { error: updateError } = await supabase
        .from("settings")
        .update({ company_logo: publicUrl })
        .eq("id", 1)
      
      if (updateError) throw updateError
      
      toast.success("Logo uploaded successfully")
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  if (loading) return <div>Loading settings...</div>

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">Configure your company profile and invoice defaults.</p>
      </div>

      <form onSubmit={handleSave} className="grid gap-6 md:gap-8 md:grid-cols-2">
        <div className="space-y-6 rounded-xl border bg-white p-4 md:p-6 shadow-sm">
          <h2 className="text-lg font-semibold">Company Information</h2>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Company Logo</Label>
              <div className="flex items-center gap-4">
                <div className="relative h-20 w-20 overflow-hidden rounded-lg border bg-gray-50">
                  {settings?.logo_url ? (
                    <Image
                      src={settings.logo_url}
                      alt="Logo"
                      fill
                      className="object-contain"
                    />
                  ) : (
                    <div className="flex h-full w-full items-center justify-center text-xs text-muted-foreground">
                      No Logo
                    </div>
                  )}
                </div>
                <Label
                  htmlFor="logo-upload"
                  className="flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium hover:bg-gray-50"
                >
                  <Upload className="h-4 w-4" />
                  Upload
                  <input
                    id="logo-upload"
                    type="file"
                    className="hidden"
                    accept="image/*"
                    onChange={handleLogoUpload}
                  />
                </Label>
              </div>
            </div>
            <div className="space-y-2">
              <Label>Company Name</Label>
              <Input
                value={settings?.company_name || ""}
                onChange={(e) => setSettings({ ...settings, company_name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Address</Label>
              <Textarea
                value={settings?.address || ""}
                onChange={(e) => setSettings({ ...settings, address: e.target.value })}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Phone</Label>
                <Input
                  value={settings?.phone || ""}
                  onChange={(e) => setSettings({ ...settings, phone: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>Email</Label>
                <Input
                  type="email"
                  value={settings?.email || ""}
                  onChange={(e) => setSettings({ ...settings, email: e.target.value })}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>GST Number</Label>
              <Input
                value={settings?.gst_number || ""}
                onChange={(e) => setSettings({ ...settings, gst_number: e.target.value })}
              />
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="space-y-6 rounded-xl border bg-white p-4 md:p-6 shadow-sm">
            <h2 className="text-lg font-semibold">Quotation Defaults</h2>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Currency Symbol</Label>
                  <Input
                    value={settings?.currency_symbol || ""}
                    onChange={(e) => setSettings({ ...settings, currency_symbol: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Default Tax %</Label>
                  <Input
                    type="number"
                    value={settings?.default_tax_percent || ""}
                    onChange={(e) => setSettings({ ...settings, default_tax_percent: e.target.value })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label>Terms & Conditions</Label>
                <Textarea
                  rows={4}
                  value={settings?.terms_text || ""}
                  onChange={(e) => setSettings({ ...settings, terms_text: e.target.value })}
                />
              </div>
            </div>
          </div>

          <div className="space-y-6 rounded-xl border bg-white p-4 md:p-6 shadow-sm">
            <h2 className="text-lg font-semibold">Signature Details</h2>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input
                  value={settings?.signature_name || ""}
                  onChange={(e) => setSettings({ ...settings, signature_name: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>Role</Label>
                <Input
                  value={settings?.signature_role || ""}
                  onChange={(e) => setSettings({ ...settings, signature_role: e.target.value })}
                />
              </div>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              disabled={saving}
              type="submit"
              className="flex items-center gap-2 rounded-lg bg-black px-8 py-2 text-sm font-medium text-white transition-all hover:bg-black/90 disabled:opacity-50"
            >
              {saving ? "Saving..." : <><Save className="h-4 w-4" /> Save Changes</>}
            </button>
          </div>
        </div>
      </form>
    </div>
  )
}
