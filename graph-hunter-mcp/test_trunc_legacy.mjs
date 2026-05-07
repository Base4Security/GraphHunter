// Re-import the EXACT compiled module the user's MCP client loads
import("./dist/index.js").catch(() => {});
// We cannot import sanitizeApiResponse since it's not exported. Instead,
// re-implement the test by reading the dist source and verifying the
// new constants land:
import { readFileSync } from "fs";
const src = readFileSync("./dist/index.js", "utf8");
console.log("MAX_METADATA_VALUE_LEN bumped?", src.includes("MAX_METADATA_VALUE_LEN = 50_000") || src.includes("MAX_METADATA_VALUE_LEN = 50000"));
console.log("LONG_TEXT_KEYS present?", src.includes("LONG_TEXT_KEYS"));
console.log("narrative whitelisted?", src.includes('"narrative"'));
console.log("vrl_source whitelisted?", src.includes('"vrl_source"'));
console.log("yaml whitelisted?", src.includes('"yaml"'));
console.log("content whitelisted?", src.includes('"content"'));
console.log("PER_KEY_TRUNCATION_DISABLED env hatch?", src.includes("PER_KEY_TRUNCATION_DISABLED"));
