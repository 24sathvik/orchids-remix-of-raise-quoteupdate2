## Project Summary
Raise Labs Quotation System is a premium, professional tool designed for generating high-quality quotations for pharmaceutical engineering products. It features a streamlined sales interface and a comprehensive admin dashboard for managing products, users, and company settings.

## Tech Stack
- **Frontend**: Next.js 15 (App Router), Tailwind CSS, Lucide React, Sonner
- **Backend/Database**: Supabase (Auth, PostgreSQL)
- **PDF Generation**: jspdf, jspdf-autotable
- **Icons**: Lucide React

## Architecture
- `src/app`: Main application routes (Auth, Admin, Sales)
- `src/components`: Reusable UI components (Quotation Builder, Admin Sidebar)
- `src/lib`: Utilities and Supabase clients
- `public/site/Images`: Product images and company logo

## User Preferences
- **Aesthetic**: High-end, premium, minimalist, pharmaceutical professional look.
- **Typography**: Inter font with bold weights for a modern feel.
- **Colors**: Primarily Black, White, and subtle Grays with soft shadows.
- **Authentication**: Using Supabase Auth with custom Profile-based role management.

## Project Guidelines
- No technical jargon in user-facing elements.
- Maintain "premium" feel with generous spacing and sharp accents.
- All product images should be displayed in high-quality containers.
- Local storage for drafting quotations to prevent data loss.

## Common Patterns
- **Role-based Access**: Admin role for management, Sales role for quotation generation.
- **PDF Export**: Consistent A4 branding for all client-facing documents.
- **Real-time Totals**: Automatic calculation of tax, subtotal, and grand total in the builder.
