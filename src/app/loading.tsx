
export default function Loading() {
    return (
        <div className="flex min-h-screen items-center justify-center bg-gray-50">
            <div className="flex flex-col items-center gap-4">
                <div className="h-12 w-12 animate-spin rounded-xl border-4 border-gray-200 border-t-black" />
                <p className="animate-pulse text-sm font-bold text-gray-400">Loading application...</p>
            </div>
        </div>
    )
}
