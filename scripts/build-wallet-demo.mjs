import { build } from 'esbuild';

await build({
  entryPoints: ['client/wallet-demo.mjs'],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  outfile: 'dist/wallet-demo.js',
  sourcemap: false,
});
