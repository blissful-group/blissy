import config from "./rules/config.mjs";
import defaults from "./rules/defaults.mjs";
import json from "./rules/json.mjs";
import typescript from "./rules/typescript.mjs";

/** @type {import('eslint').Linter.Config[]} */
export default [...config, ...defaults, ...json, ...typescript];
