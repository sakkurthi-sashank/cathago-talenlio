import "express-session";

declare module "express-session" {
  interface SessionData {
    user?: {
      id: number;
      email: string;
      firstname: string;
      lastname: string;
      role: string;
      credits: number;
    };
  }
}
