import type { NextConfig } from "next";

// The hardcoded root pins Turbopack/tracing at the shared-node_modules monorepo
// dir LOCALLY. On Vercel the project is uploaded standalone, so that path lives
// outside the build root and Turbopack fails ("distDirRoot navigates out"); let
// Vercel infer the root there instead.
const LOCAL_ROOT = "/Users/crypto/Downloads/concept-machine";
const onVercel = !!process.env.VERCEL;

const nextConfig: NextConfig = {
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  ...(onVercel
    ? {}
    : { turbopack: { root: LOCAL_ROOT }, outputFileTracingRoot: LOCAL_ROOT }),
};
export default nextConfig;
