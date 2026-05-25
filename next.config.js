/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  images: {
    unoptimized: true // Required for static HTML export compatibility
  }
};

module.exports = nextConfig;
