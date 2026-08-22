// Helper de ownership sintético, resolvível cross-file.
export async function ensureOwnsNote(admin: any, uid: string, noteId: string) {
  const { data } = await admin.from("notes").select("id,user_id").eq("id", noteId).maybeSingle();
  if (!data) throw new Error("404");
  if (data.user_id !== uid) throw new Error("403");
  return data;
}
