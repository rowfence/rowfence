import type { NextConfig } from "next";

// useCache: the "use cache" directive, for the page that tries to cache a signed-in read with it (check 15)
const config: NextConfig = { experimental: { useCache: true } };

export default config;
