# Supabase setup — Phase 2A

This folder creates the central PostgreSQL data model and initial Row Level Security (RLS) rules.

## Setup
1. Create a Supabase project for the Gorgan building-services app.
2. Open **SQL Editor → New query**.
3. Copy and run `schema.sql`.
4. Confirm that the five public tables and the rating summary view were created.
5. Do not place a Supabase service-role key in GitHub Pages or any browser JavaScript.

## Phone sign-in
Phone OTP requires enabling Phone in **Authentication → Providers** and configuring an SMS provider supported for the target country. The frontend will use Supabase Auth `signInWithOtp({ phone })` and `verifyOtp({ phone, token, type: 'sms' })`. Test with a configured test number before paying for SMS delivery.

## First administrator
New Auth users are always created as `customer`. Do not add an admin selector to the public app. Promote the first administrator only from the Supabase SQL editor after verifying the account:
```sql
update public.profiles
set role = 'admin'
where phone = '+98YOUR_VERIFIED_NUMBER';
```
Do not expose the service-role key to the browser.

## Important integration work still required
- Add the project URL and publishable/anon key to a local, untracked config file (never commit secrets).
- Replace LocalStorage operations in the UI with authenticated Supabase queries.
- Add server-side functions for technician assignment, admin actions, payment callbacks and subscription activation.
- Add stricter transition rules and auditing before production. The starter RLS policies are a foundation, not a complete production security review.
- Configure an SMS provider that can deliver to Iranian mobile numbers; provider availability, sender registration, compliance and cost must be confirmed before promising SMS OTP in Iran.

See the official [Supabase phone login guide](https://supabase.com/docs/guides/auth/phone-login).
