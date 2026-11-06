# Supabase clean setup — Building Services Gorgan

This is the clean baseline database schema. It is non-destructive and does not drop tables or records. It does not yet connect the GitHub Pages frontend.

## Run the schema
1. Open the intended Supabase project and confirm its project URL.
2. Open SQL Editor, then New query.
3. Open the schema.sql file in this folder and copy the complete contents.
4. Paste into SQL Editor and press Run once.
5. If any error appears, stop and send the exact error text. Do not run random fragments or manually drop tables.

## Authentication
Enable Phone under Authentication providers and configure an SMS provider that can deliver to Iranian mobile numbers. Test a real OTP delivery before relying on phone login. The signup metadata account_type may be customer or technician. Admin is never self-selectable.

## Important
- The service_areas table is intentionally empty until the verified Gorgan neighborhood list is added.
- Four subscription plans are inserted with zero-price placeholders. Set real toman prices before offering subscriptions.
- Payment activation must be server-side; browser code must never mark an order as paid.
- Use only the project URL and publishable/anon key in browser code. Never expose database password, service_role key, or secret key.
- Assign the first administrator manually in SQL Editor after verifying the phone number.
- The current frontend still uses localStorage. OTP, Supabase queries, technician onboarding, request realtime and multi-device tests are a separate integration phase.
