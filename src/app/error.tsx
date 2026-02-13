
'use client'

import { useEffect } from 'react'
import { Button } from '@/components/ui/button'

export default function Error({
    error,
    reset,
}: {
    error: Error & { digest?: string }
    reset: () => void
}) {
    useEffect(() => {
        console.error(error)
    }, [error])

    return (
        <div className="flex min-h-screen flex-col items-center justify-center bg-gray-50 px-4 text-center">
            <h2 className="mb-4 text-2xl font-black text-black">Something went wrong!</h2>
            <p className="mb-8 max-w-md text-gray-500">{error.message || "An unexpected error occurred."}</p>
            <div className="flex gap-4">
                <Button
                    onClick={() => window.location.href = '/'}
                    variant="outline"
                    className="rounded-xl font-bold"
                >
                    Go Home
                </Button>
                <Button
                    onClick={() => reset()}
                    className="rounded-xl bg-black font-bold text-white hover:bg-gray-800"
                >
                    Try again
                </Button>
            </div>
        </div>
    )
}
