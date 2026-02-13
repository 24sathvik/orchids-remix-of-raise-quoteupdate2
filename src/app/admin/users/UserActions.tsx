'use client'

import { useState } from 'react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { MoreHorizontal, Key, Power, PowerOff, Loader2 } from 'lucide-react'
import { toggleUserStatus, resetUserPassword } from './actions'
import { toast } from 'sonner'

export default function UserActions({ user }: { user: any }) {
  const [isResetOpen, setIsResetOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [newPassword, setNewPassword] = useState('')

  async function handleToggleStatus() {
    setIsLoading(true)
    const result = await toggleUserStatus(user.id, !user.active)
    setIsLoading(false)

    if (result.error) {
      toast.error(result.error)
    } else {
      toast.success(`User ${user.active ? 'deactivated' : 'activated'} successfully`)
    }
  }

  async function handleResetPassword(e: React.FormEvent) {
    e.preventDefault()
    setIsLoading(true)
    const result = await resetUserPassword(user.id, newPassword)
    setIsLoading(false)

    if (result.error) {
      toast.error(result.error)
    } else {
      toast.success('Password reset successfully')
      setIsResetOpen(false)
      setNewPassword('')
    }
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="h-8 w-8 p-0">
            <MoreHorizontal className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-[200px]">
          <DropdownMenuLabel>Actions</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => setIsResetOpen(true)} className="gap-2 cursor-pointer">
            <Key className="h-4 w-4" />
            Reset Password
          </DropdownMenuItem>
          <DropdownMenuItem 
            onClick={handleToggleStatus} 
            className={`gap-2 cursor-pointer ${user.active ? 'text-red-600 focus:text-red-600' : 'text-emerald-600 focus:text-emerald-600'}`}
          >
            {user.active ? (
              <>
                <PowerOff className="h-4 w-4" />
                Deactivate Account
              </>
            ) : (
              <>
                <Power className="h-4 w-4" />
                Activate Account
              </>
            )}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog open={isResetOpen} onOpenChange={setIsResetOpen}>
        <DialogContent className="sm:max-w-[425px]">
          <form onSubmit={handleResetPassword}>
            <DialogHeader>
              <DialogTitle>Reset Password</DialogTitle>
              <DialogDescription>
                Enter a new temporary password for {user.name}.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="new-password">New Password</Label>
                <Input 
                  id="new-password" 
                  type="password" 
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required 
                />
              </div>
            </div>
            <DialogFooter>
              <Button 
                type="submit" 
                className="bg-black hover:bg-gray-800 text-white w-full"
                disabled={isLoading || !newPassword}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Resetting...
                  </>
                ) : (
                  'Reset Password'
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}
