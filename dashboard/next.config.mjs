/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  images: { unoptimized: true },
  // GitHub Pages serves from a subpath; Vercel from root. Set BASE_PATH at build time if needed.
  basePath: process.env.BASE_PATH || "",
  trailingSlash: true,
};

export default nextConfig;
