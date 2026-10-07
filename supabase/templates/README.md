# Supabase Auth email templates

Source of truth for the Auth emails Supabase sends. Hosted Supabase does not read these files:
paste each one in **Supabase Dashboard -> Authentication -> Email Templates** and save.

| Dashboard tab | Subject | File |
|---|---|---|
| Confirm signup | Confirm your Zelsis account | confirmation.html |
| Invite user | You're invited to Zelsis | invite.html |
| Magic Link | Your Zelsis sign-in link | magic_link.html |
| Change Email Address | Confirm your new Zelsis email | email_change.html |
| Reset Password | Reset your Zelsis password | recovery.html |

The `{{ .ConfirmationURL }}`, `{{ .Token }}`, `{{ .NewEmail }}` and `{{ .SiteURL }}` placeholders are
Supabase template variables; keep them exactly as written.
