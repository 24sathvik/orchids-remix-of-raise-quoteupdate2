
'use client'

export default function GlobalError({
    error,
    reset,
}: {
    error: Error & { digest?: string }
    reset: () => void
}) {
    return (
        <html>
            <body>
                <div className="flex min-h-screen flex-col items-center justify-center bg-gray-50 px-4 text-center">
                    <h2 className="mb-4 text-2xl font-black text-black">Something went wrong!</h2>
                    <p className="mb-8 max-w-md text-gray-500">A application-level error occurred.</p>
                    <button
                        onClick={() => reset()}
                        className="rounded-xl bg-black px-6 py-2 font-bold text-white hover:bg-gray-800"
                    >
                        Try again
                    </button>
                </div>
            </body>
        </html>
    )
}
