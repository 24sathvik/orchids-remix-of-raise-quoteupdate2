"use client"

import { useEffect, useState } from "react"
import { Plus, Search, Key, Power, PowerOff, Edit2, Trash2, X } from "lucide-react"
import { toast } from "sonner"

import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"

interface Profile {
  id: string
  name: string
  email: string
  role: string
  active: boolean
  created_at: string
  phone: string | null
}

export default function UsersPage() {
  const [users, setUsers] = useState<Profile[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState("")
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [isEditOpen, setIsEditOpen] = useState(false)
  const [isResetOpen, setIsResetOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<Profile | null>(null)
  
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    role: "sales",
    phone: "",
  })

  useEffect(() => {
    fetchUsers()
  }, [])

  const fetchUsers = async () => {
    try {
      const res = await fetch("/api/admin/users")
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      setUsers(data)
    } catch (err: any) {
      toast.error(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const res = await fetch("/api/admin/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      })
      
      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || `HTTP ${res.status}`)
      }
      
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      
      toast.success("User created successfully")
      setIsCreateOpen(false)
      fetchUsers()
      setFormData({ name: "", email: "", password: "", role: "sales", phone: "" })
    } catch (err: any) {
      console.error("Create user error:", err)
      toast.error(err.message || "Failed to create user")
    }
  }

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedUser) return
    try {
      const res = await fetch("/api/admin/users", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          id: selectedUser.id, 
          name: formData.name, 
          role: formData.role,
          phone: formData.phone
        }),
      })
      
      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || `HTTP ${res.status}`)
      }
      
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      
      toast.success("User updated successfully")
      setIsEditOpen(false)
      fetchUsers()
    } catch (err: any) {
      console.error("Update user error:", err)
      toast.error(err.message || "Failed to update user")
    }
  }

  const handleToggleStatus = async (user: Profile) => {
    try {
      const res = await fetch("/api/admin/users", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: user.id, active: !user.active }),
      })
      
      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || `HTTP ${res.status}`)
      }
      
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      toast.success(`User ${user.active ? "deactivated" : "activated"} successfully`)
      fetchUsers()
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this user? This action cannot be undone.")) return
    try {
      const res = await fetch(`/api/admin/users?id=${id}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
      })
      
      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || `HTTP ${res.status}`)
      }
      
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      
      toast.success("User deleted successfully")
      fetchUsers()
    } catch (err: any) {
      console.error("Delete user error:", err)
      toast.error(err.message || "Failed to delete user")
    }
  }

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedUser) return
    try {
      const res = await fetch("/api/admin/users", {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: selectedUser.id, password: formData.password }),
        })
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      toast.success("Password reset successfully")
      setIsResetOpen(false)
      setFormData({ ...formData, password: "" })
    } catch (err: any) {
      toast.error(err.message)
    }
  }

  const filteredUsers = users.filter(
    (u) =>
      u.name?.toLowerCase().includes(search.toLowerCase()) ||
      u.email?.toLowerCase().includes(search.toLowerCase()) ||
      u.role?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-black">Users</h1>
          <p className="text-sm font-medium text-gray-400">Manage your sales team and administrators.</p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <button className="flex items-center gap-2 rounded-xl bg-black px-6 py-3 text-sm font-bold text-white shadow-xl shadow-black/20 transition-all hover:bg-black/90 active:scale-95">
              <Plus className="h-4 w-4" />
              Add User
            </button>
          </DialogTrigger>
          <DialogContent className="rounded-2xl sm:max-w-[425px]">
            <form onSubmit={handleCreate}>
              <DialogHeader>
                <DialogTitle className="text-xl font-black">Create New User</DialogTitle>
                <DialogDescription className="font-medium text-gray-400">
                  Enter user details to create a new account.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-6 py-6">
                <div className="space-y-2">
                  <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Full Name</Label>
                  <Input
                    required
                    className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white"
                    placeholder="Enter full name"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Email</Label>
                  <Input
                    required
                    type="email"
                    className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white"
                    placeholder="name@example.com"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Password</Label>
                  <Input
                    required
                    type="password"
                    className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white"
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                    <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Role</Label>
                    <Select
                      value={formData.role}
                      onValueChange={(v) => setFormData({ ...formData, role: v })}
                    >
                      <SelectTrigger className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="rounded-xl border-none shadow-2xl">
                        <SelectItem value="admin">Admin</SelectItem>
                        <SelectItem value="sales">Sales</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Phone Number</Label>
                    <Input
                      className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white"
                      placeholder="+91 91777 70365"
                      value={formData.phone}
                      onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                    />
                  </div>
                </div>
                <DialogFooter>
                  <button
                    type="submit"
                    className="w-full rounded-xl bg-black py-4 text-sm font-bold text-white shadow-xl shadow-black/20 transition-all hover:bg-black/90 active:scale-95"
                  >
                    Create User
                  </button>
                </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <Input
            placeholder="Search by name, email or role..."
            className="h-12 rounded-xl border-none bg-white pl-11 shadow-sm ring-1 ring-gray-100 focus:ring-black transition-all"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border-none bg-white shadow-sm ring-1 ring-gray-100">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-gray-50 hover:bg-transparent">
                <TableHead className="h-14 px-6 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400 whitespace-nowrap">User</TableHead>
                <TableHead className="h-14 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400 whitespace-nowrap">Role</TableHead>
                <TableHead className="h-14 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400 whitespace-nowrap">Status</TableHead>
                <TableHead className="h-14 text-[10px] font-black uppercase tracking-[0.2em] text-gray-400 whitespace-nowrap">Joined</TableHead>
                <TableHead className="h-14 px-6 text-right text-[10px] font-black uppercase tracking-[0.2em] text-gray-400 whitespace-nowrap">Actions</TableHead>
              </TableRow>
            </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} className="h-32 text-center text-sm font-medium text-gray-400">
                  Fetching personnel data...
                </TableCell>
              </TableRow>
            ) : filteredUsers.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-32 text-center text-sm font-medium text-gray-400">
                  No matching users found.
                </TableCell>
              </TableRow>
            ) : (
              filteredUsers.map((user) => (
                <TableRow key={user.id} className="border-gray-50 group hover:bg-gray-50/50 transition-colors">
                  <TableCell className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gray-50 text-[10px] font-black text-black ring-1 ring-gray-100 uppercase">
                        {user.name?.[0] || user.email?.[0] || 'U'}
                      </div>
                      <div className="flex flex-col">
                        <span className="font-bold text-black">{user.name || 'No Name'}</span>
                        <span className="text-[10px] font-medium text-gray-400">{user.email}</span>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge className={`rounded-full px-3 py-1 text-[10px] font-black uppercase tracking-wider shadow-none ${
                      user.role === "admin" 
                        ? "bg-black text-white" 
                        : "bg-gray-100 text-gray-500"
                    }`}>
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className={`h-1.5 w-1.5 rounded-full ${user.active ? "bg-green-500" : "bg-red-500"}`} />
                      <span className={`text-xs font-bold ${user.active ? "text-green-600" : "text-red-600"}`}>
                        {user.active ? "Active" : "Inactive"}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs font-bold text-gray-400 uppercase tracking-tighter">
                    {new Date(user.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                  </TableCell>
                  <TableCell className="px-6 text-right">
                    <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                          onClick={() => {
                            setSelectedUser(user)
                            setFormData({ ...formData, name: user.name, email: user.email, role: user.role, phone: user.phone || "" })
                            setIsEditOpen(true)
                          }}
                          className="rounded-lg p-2 text-gray-400 hover:bg-gray-100 hover:text-black transition-all"
                          title="Edit User"
                        >
                          <Edit2 className="h-4 w-4" />
                        </button>
                      <button
                        onClick={() => {
                          setSelectedUser(user)
                          setIsResetOpen(true)
                        }}
                        className="rounded-lg p-2 text-gray-400 hover:bg-gray-100 hover:text-black transition-all"
                        title="Reset Password"
                      >
                        <Key className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleToggleStatus(user)}
                        className={`rounded-lg p-2 transition-all ${
                          user.active 
                            ? "text-gray-400 hover:bg-red-50 hover:text-red-500" 
                            : "text-gray-400 hover:bg-green-50 hover:text-green-500"
                        }`}
                        title={user.active ? "Deactivate" : "Activate"}
                      >
                        {user.active ? <PowerOff className="h-4 w-4" /> : <Power className="h-4 w-4" />}
                      </button>
                      <button
                        onClick={() => handleDelete(user.id)}
                        className="rounded-lg p-2 text-gray-400 hover:bg-red-50 hover:text-red-500 transition-all"
                        title="Delete User"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        </div>
      </div>

      {/* Edit Dialog */}
      <Dialog open={isEditOpen} onOpenChange={setIsEditOpen}>
        <DialogContent className="rounded-2xl sm:max-w-[425px]">
          <form onSubmit={handleUpdate}>
            <DialogHeader>
              <DialogTitle className="text-xl font-black">Edit User</DialogTitle>
              <DialogDescription className="font-medium text-gray-400">
                Update user profile information.
              </DialogDescription>
            </DialogHeader>
              <div className="grid gap-6 py-6">
                <div className="space-y-2">
                  <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Full Name</Label>
                  <Input
                    required
                    className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Phone Number</Label>
                  <Input
                    className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white"
                    placeholder="+91 91777 70365"
                    value={formData.phone}
                    onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">Role</Label>
                  <Select
                    value={formData.role}
                    onValueChange={(v) => setFormData({ ...formData, role: v })}
                  >
                    <SelectTrigger className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="rounded-xl border-none shadow-2xl">
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="sales">Sales</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            <DialogFooter>
              <button
                type="submit"
                className="w-full rounded-xl bg-black py-4 text-sm font-bold text-white shadow-xl shadow-black/20 transition-all hover:bg-black/90 active:scale-95"
              >
                Save Changes
              </button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Reset Password Dialog */}
      <Dialog open={isResetOpen} onOpenChange={setIsResetOpen}>
        <DialogContent className="rounded-2xl sm:max-w-[425px]">
          <form onSubmit={handleResetPassword}>
            <DialogHeader>
              <DialogTitle className="text-xl font-black">Reset Password</DialogTitle>
              <DialogDescription className="font-medium text-gray-400">
                Enter a new password for {selectedUser?.name}.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-6 py-6">
              <div className="space-y-2">
                <Label className="text-xs font-bold uppercase tracking-wider text-gray-500">New Password</Label>
                <Input
                  required
                  type="password"
                  className="h-12 rounded-xl border-gray-100 bg-gray-50/50 focus:bg-white"
                  placeholder="••••••••"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                />
              </div>
            </div>
            <DialogFooter>
              <button
                type="submit"
                className="w-full rounded-xl bg-black py-4 text-sm font-bold text-white shadow-xl shadow-black/20 transition-all hover:bg-black/90 active:scale-95"
              >
                Update Password
              </button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
