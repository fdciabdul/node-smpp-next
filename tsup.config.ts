import { defineConfig } from 'tsup';

export default defineConfig({
	entry: { smpp: 'src/smpp.ts' },
	format: ['cjs', 'esm'],
	dts: true,
	sourcemap: true,
	clean: true,
	target: 'node18',
	outDir: 'dist',
});
