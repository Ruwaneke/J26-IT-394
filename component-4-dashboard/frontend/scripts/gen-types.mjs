// Generates src/types/schema.generated.ts from ml/analytics.schema.json.
// --check: fail if the committed file is out of date with the schema.
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { compile } from "json-schema-to-typescript";

const schemaPath = fileURLToPath(new URL("../../ml/analytics.schema.json", import.meta.url));
const outPath = fileURLToPath(new URL("../src/types/schema.generated.ts", import.meta.url));

const schema = JSON.parse(await readFile(schemaPath, "utf8"));
const banner = "/* Generated from ml/analytics.schema.json by scripts/gen-types.mjs. Do not edit by hand. */";
const ts = await compile(schema, "AnalyticsContract", {
  bannerComment: banner,
  additionalProperties: false,
  strictIndexSignatures: false,
  ignoreMinAndMaxItems: true,
  format: false,
});

if (process.argv.includes("--check")) {
  const current = await readFile(outPath, "utf8").catch(() => "");
  if (current !== ts) {
    console.error("schema.generated.ts is out of date. Run: npm run gen:types");
    process.exit(1);
  }
  console.log("schema.generated.ts matches ml/analytics.schema.json");
} else {
  await writeFile(outPath, ts);
  console.log(`Wrote ${outPath}`);
}
