// A background job (Next.js after(), a queue worker): it acts for service 1, whatever started it
import { current, job } from "@rowstile/client";
import { db } from "./db.ts";

export const digest = job(["service", 1], async () => ({ count: await db.project.count(), who: current() }));
