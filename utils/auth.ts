import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/authOptions";

/**
 * Mengecek apakah user yang sedang login memiliki role admin
 */
export async function isAdmin(): Promise<boolean> {
  const session = (await getServerSession(authOptions)) as any;
  return session?.user?.role === "admin";
}

/**
 * Melempar error jika bukan admin (untuk proteksi server-side)
 */
export async function requireAdmin() {
  const admin = await isAdmin();
  if (!admin) {
    throw new Error("Admin access required");
  }
}
