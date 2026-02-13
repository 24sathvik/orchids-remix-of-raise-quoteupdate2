
import postgres from 'postgres';
import { createClient } from '@supabase/supabase-js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// 1. Load Environment Variables
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../.env.local');

if (fs.existsSync(envPath)) {
    const envConfig = fs.readFileSync(envPath, 'utf-8');
    envConfig.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            process.env[key.trim()] = value.trim();
        }
    });
}

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const DATABASE_URL = process.env.DATABASE_URL;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !DATABASE_URL) {
    console.error('Missing environment variables (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, DATABASE_URL). Please check .env.local');
    process.exit(1);
}

// 2. Initialize Clients
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});
const sql = postgres(DATABASE_URL, { ssl: 'require' });

async function main() {
    const email = 'admin@raiselabs.com';
    const password = '123456789';
    const name = 'Admin User';

    console.log(`Setting up admin user: ${email}...`);

    try {
        // 3. Create or Update User via Admin API
        const { data: { users }, error: listError } = await supabaseAdmin.auth.admin.listUsers();
        if (listError) throw listError;

        const existingUser = users.find(u => u.email === email);
        let userId;

        if (existingUser) {
            console.log('User already exists, updating password and metadata...');
            userId = existingUser.id;
            const { error: updateError } = await supabaseAdmin.auth.admin.updateUserById(
                userId,
                {
                    password: password,
                    email_confirm: true,
                    user_metadata: { full_name: name, role: 'admin' },
                    app_metadata: { role: 'admin' }
                }
            );
            if (updateError) throw updateError;
        } else {
            console.log('Creating new admin user...');
            const { data: newUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
                email,
                password,
                email_confirm: true,
                user_metadata: { full_name: name, role: 'admin' },
                app_metadata: { role: 'admin' }
            });
            if (createError) throw createError;
            userId = newUser.user.id;
        }

        console.log(`User ID: ${userId} configured in Auth.`);

        // 4. Upsert Profile in Public Table
        // We use the 'id' from auth to match the profile
        await sql`
            INSERT INTO public.profiles (id, full_name, email, role, active)
            VALUES (${userId}, ${name}, ${email}, 'admin', true)
            ON CONFLICT (id) DO UPDATE
            SET role = 'admin', active = true, full_name = ${name}
        `;
        console.log('Profile updated to admin role in DB.');

        console.log('Admin setup complete!');
        process.exit(0);

    } catch (err) {
        console.error('Error during setup:', err);
        process.exit(1);
    }
}

main();
