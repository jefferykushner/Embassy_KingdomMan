// Kingdom Men account service: joining, admin password resets, group code and visitor login.
import { createClient } from "npm:@supabase/supabase-js@2";

const URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const DOMAIN = "kingdom-men-prayer.netlify.app"; // logins are username@DOMAIN; no email is ever sent there
const db = createClient(URL, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } });

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });
const fail = (msg: string, status = 400) => json({ error: msg }, status);

const slug = (s: string) => s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]/g, "");
const emailFor = (u: string) => `${u}@${DOMAIN}`;
const okPassword = (p: unknown) => typeof p === "string" && p.length >= 6 && p.length <= 72;

async function setting(k: string) {
  const { data } = await db.rpc("km_get_setting", { k });
  return (data as string) || "";
}
const sameCode = (a: string, b: string) => !!a && !!b && a.trim().toUpperCase() === b.trim().toUpperCase();

async function freeUsername(base: string) {
  const root = base || "brother";
  for (let i = 0; i < 50; i++) {
    const u = i === 0 ? root : root + (i + 1);
    const { data } = await db.from("men").select("id").eq("username", u).maybeSingle();
    const { data: v } = await db.rpc("km_visitor_get");
    const vis = Array.isArray(v) && v[0] && v[0].username === u;
    if (!data && !vis) return u;
  }
  throw new Error("Could not pick a username");
}

async function callerIsAdmin(req: Request) {
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return false;
  const { data, error } = await db.auth.getUser(token);
  if (error || !data?.user) return false;
  const { data: m } = await db.from("men").select("is_admin").eq("user_id", data.user.id).maybeSingle();
  return !!m?.is_admin;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return fail("POST only", 405);
  let b: any;
  try { b = await req.json(); } catch { return fail("Bad request"); }
  const action = b?.action;

  try {
    // ---------- Joining ----------
    if (action === "names") {
      const group = await setting("group_code"), admin = await setting("admin_code");
      if (!sameCode(b.code, group) && !sameCode(b.code, admin)) return fail("That group code isn't right. Check the WhatsApp chat.", 403);
      const { data } = await db.from("men").select("id,name,user_id").order("name");
      return json({ names: (data || []).map((m: any) => ({ id: m.id, name: m.name, joined: !!m.user_id })) });
    }

    if (action === "register") {
      const { data: man } = await db.from("men").select("id,name,user_id,is_admin").eq("id", b.man_id).maybeSingle();
      if (!man) return fail("Please pick your name from the list.");
      const need = man.is_admin ? await setting("admin_code") : await setting("group_code");
      if (!sameCode(b.code, need)) return fail(man.is_admin ? "This name needs the admin setup code." : "That group code isn't right.", 403);
      if (man.user_id) return fail(`${man.name} has already joined. If that's you and you forgot your password, ask Jeffery to reset it.`, 409);
      if (!okPassword(b.password)) return fail("Password needs at least 6 characters.");
      const username = await freeUsername(slug(man.name));
      const { data: created, error } = await db.auth.admin.createUser({
        email: emailFor(username), password: b.password, email_confirm: true, user_metadata: { username, name: man.name },
      });
      if (error || !created?.user) return fail("Couldn't create the account: " + (error?.message || "unknown"), 500);
      const { data: linked, error: lerr } = await db.from("men").update({ user_id: created.user.id, username })
        .eq("id", man.id).is("user_id", null).select("id");
      if (lerr || !linked?.length) {
        await db.auth.admin.deleteUser(created.user.id);
        return fail(`${man.name} has already joined.`, 409);
      }
      return json({ username });
    }

    // ---------- Admin only ----------
    if (!String(action || "").startsWith("admin_")) return fail("Unknown action");
    if (!(await callerIsAdmin(req))) return fail("Admins only", 403);

    if (action === "admin_overview") {
      const { data } = await db.from("men").select("id,name,username,user_id,is_admin").order("name");
      const { data: v } = await db.rpc("km_visitor_get");
      return json({
        men: (data || []).map((m: any) => ({ id: m.id, name: m.name, username: m.username, joined: !!m.user_id, is_admin: m.is_admin })),
        group_code: await setting("group_code"),
        visitor_username: Array.isArray(v) && v[0] ? v[0].username : null,
      });
    }

    if (action === "admin_reset") {
      if (!okPassword(b.password)) return fail("Password needs at least 6 characters.");
      const { data: man } = await db.from("men").select("user_id,name").eq("id", b.man_id).maybeSingle();
      if (!man?.user_id) return fail("He hasn't joined yet.");
      const { error } = await db.auth.admin.updateUserById(man.user_id, { password: b.password });
      if (error) return fail(error.message, 500);
      return json({ ok: true });
    }

    if (action === "admin_unlink") {
      const { data: man } = await db.from("men").select("user_id,is_admin").eq("id", b.man_id).maybeSingle();
      if (!man?.user_id) return json({ ok: true });
      if (man.is_admin) return fail("You can't remove the admin's own login here.");
      await db.from("men").update({ user_id: null, username: null }).eq("id", b.man_id);
      await db.auth.admin.deleteUser(man.user_id);
      return json({ ok: true });
    }

    if (action === "admin_set_code") {
      const code = String(b.code || "").trim();
      if (code.length < 4) return fail("Use at least 4 characters.");
      await db.rpc("km_set_setting", { k: "group_code", v: code });
      return json({ ok: true });
    }

    if (action === "admin_set_visitor") {
      const username = slug(String(b.username || ""));
      if (username.length < 3) return fail("Visitor username needs at least 3 letters or numbers.");
      if (!okPassword(b.password)) return fail("Password needs at least 6 characters.");
      const { data: clash } = await db.from("men").select("id").eq("username", username).maybeSingle();
      if (clash) return fail("A brother already uses that username.");
      const { data: v } = await db.rpc("km_visitor_get");
      const cur = Array.isArray(v) && v[0] ? v[0] : null;
      let uid = cur?.user_id as string | undefined;
      if (uid) {
        const { error } = await db.auth.admin.updateUserById(uid, { email: emailFor(username), password: b.password, email_confirm: true });
        if (error) return fail(error.message, 500);
      } else {
        const { data: created, error } = await db.auth.admin.createUser({
          email: emailFor(username), password: b.password, email_confirm: true, user_metadata: { username, visitor: true },
        });
        if (error || !created?.user) return fail(error?.message || "Couldn't create visitor", 500);
        uid = created.user.id;
      }
      await db.rpc("km_visitor_set", { uid, uname: username });
      return json({ ok: true, username });
    }

    return fail("Unknown action");
  } catch (e) {
    return fail("Server error: " + (e as Error).message, 500);
  }
});
