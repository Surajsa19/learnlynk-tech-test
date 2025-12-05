alter table public.leads enable row level security;

-- Policy: Counselors see leads they own OR leads assigned to their team.
-- Admins see all leads in their tenant.
create policy "leads_select_policy"
on public.leads
for select
using (
  tenant_id = (auth.jwt() ->> 'tenant_id')::uuid
  AND (
    (auth.jwt() ->> 'role' = 'admin')
    OR
    (
      auth.jwt() ->> 'role' = 'counselor'
      AND (
        owner_id = auth.uid()
        OR
        team_id IN (SELECT team_id FROM public.user_teams WHERE user_id = auth.uid())
      )
    )
  )
);

-- Policy: Counselors and Admins can insert leads for their tenant.
create policy "leads_insert_policy"
on public.leads
for insert
with check (
  tenant_id = (auth.jwt() ->> 'tenant_id')::uuid
  AND
  (auth.jwt() ->> 'role' IN ('admin', 'counselor'))
);
