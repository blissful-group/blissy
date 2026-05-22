import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["index.ts"],
  outDir: "dist",
  sourcemap: true,
  dts: true,
  format: ["esm", "cjs"],
  clean: true,
});
