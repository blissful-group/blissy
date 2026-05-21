import extensions from "./extensions.mjs";

export default {
  alwaysTryTypes: true,
  extensions: [".d.ts", ...extensions],
  mainFiles: ["index.gen", "index"],
  project: ["tsconfig.json", "**/*/tsconfig.json"],
};
