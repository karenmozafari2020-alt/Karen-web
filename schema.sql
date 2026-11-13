create extension if not exists pgcrypto;

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  password_hash text not null,
  password_salt text not null,
  role text not null default 'customer' check (role in ('customer','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  category text not null default 'عمومی',
  description text not null default '',
  price_rial bigint not null check (price_rial >= 0),
  image_url text not null default '',
  storage_path text not null default '',
  featured boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id),
  product_id uuid not null references public.products(id),
  product_title text not null,
  amount_rial bigint not null check (amount_rial > 0),
  status text not null default 'pending' check (status in ('pending','paid','failed')),
  payment_authority text unique,
  payment_ref_id text,
  created_at timestamptz not null default now(),
  paid_at timestamptz
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id),
  sender_role text not null check (sender_role in ('customer','admin')),
  body text not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now(),
  read_at timestamptz
);

create index if not exists orders_user_id_idx on public.orders(user_id);
create index if not exists messages_created_at_idx on public.messages(created_at);

alter table public.users enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.messages enable row level security;

-- All DB access is server-side using the private service-role key.
revoke all on public.users from anon, authenticated;
revoke all on public.products from anon, authenticated;
revoke all on public.orders from anon, authenticated;
revoke all on public.messages from anon, authenticated;

-- Create a PRIVATE Storage bucket named template-files.
-- Put downloadable ZIP files there and save their object path in products.storage_path.
