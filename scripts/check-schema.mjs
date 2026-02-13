
import postgres from 'postgres';
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

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error('Missing DATABASE_URL. Please check .env.local');
    process.exit(1);
}

const sql = postgres(DATABASE_URL, { ssl: 'require' });

async function main() {
    console.log('Checking database schema...');

    try {
        // Check if 'image_format' column exists in 'products' table
        const columns = await sql`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'products' AND column_name = 'image_format';
        `;

        if (columns.length === 0) {
            console.log("Column 'image_format' does not exist. Adding it...");
            await sql`
                ALTER TABLE products 
                ADD COLUMN image_format TEXT DEFAULT 'wide';
            `;
            console.log("Column 'image_format' added successfully.");
        } else {
            console.log("Column 'image_format' already exists.");
        }

        // Check if it exists now
        const verify = await sql`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'products' AND column_name = 'image_format';
        `;

        if (verify.length > 0) {
            console.log("Schema verification passed: 'image_format' is present.");
        } else {
            console.error("Schema verification failed!");
        }

        process.exit(0);

    } catch (err) {
        console.error('Error checking/modifying schema:', err);
        process.exit(1);
    }
}

main();
