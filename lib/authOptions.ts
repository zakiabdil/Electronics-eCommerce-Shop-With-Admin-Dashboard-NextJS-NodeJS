// File: lib/authOptions.ts

import GithubProvider from "next-auth/providers/github";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import bcrypt from "bcryptjs";
import prisma from "@/utils/db";
import { nanoid } from "nanoid";

// Gunakan 'any' agar kompatibel di NextAuth v4 + Next.js 14
export const authOptions: any = {
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials: any) {
        try {
          const user = await prisma.user.findFirst({
            where: { email: credentials.email },
          });

          if (user) {
            const isPasswordCorrect = await bcrypt.compare(
              credentials.password,
              user.password!
            );

            if (isPasswordCorrect) {
              return {
                id: user.id,
                email: user.email,
                role: user.role,
              };
            }
          }
        } catch (err: any) {
          throw new Error(err);
        }
        return null;
      },
    }),
    // Uncomment OAuth jika ingin pakai login Google/GitHub
    // GithubProvider({
    //   clientId: process.env.GITHUB_ID!,
    //   clientSecret: process.env.GITHUB_SECRET!,
    // }),
    // GoogleProvider({
    //   clientId: process.env.GOOGLE_CLIENT_ID!,
    //   clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    // }),
  ],

  callbacks: {
    async signIn({ user, account }: any) {
      // Jika pakai credentials
      if (account?.provider === "credentials") return true;

      // Jika pakai OAuth
      if (account?.provider === "github" || account?.provider === "google") {
        const existingUser = await prisma.user.findFirst({
          where: { email: user.email! },
        });

        if (!existingUser) {
          await prisma.user.create({
            data: {
              id: nanoid(),
              email: user.email!,
              role: "user",
              password: null,
            },
          });
        }
      }
      return true;
    },

    async jwt({ token, user }: any) {
      if (user) {
        token.role = (user as any).role;
        token.id = (user as any).id;
        token.iat = Math.floor(Date.now() / 1000);
      }

      // Token expire setelah 15 menit
      const now = Math.floor(Date.now() / 1000);
      const tokenAge = now - (token.iat as number);
      const maxAge = 15 * 60;

      if (tokenAge > maxAge) token.expired = true;
      return token;
    },

    async session({ session, token }: any) {
      if (token && !token.expired) {
        session.user.role = token.role as string;
        session.user.id = token.id as string;
      }
      return session;
    },
  },

  pages: {
    signIn: "/login",
    error: "/login",
  },

  session: {
    strategy: "jwt",
    maxAge: 15 * 60,
    updateAge: 5 * 60,
  },

  jwt: { maxAge: 15 * 60 },
  secret: process.env.NEXTAUTH_SECRET,
  debug: process.env.NODE_ENV === "development",
};
