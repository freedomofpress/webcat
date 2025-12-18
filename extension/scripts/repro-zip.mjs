// scripts/repro-zip.mjs
import fs from "fs";
import path from "path";
import yazl from "yazl";

const FIXED_DATE = process.env.SOURCE_DATE_EPOCH
  ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000)
  : new Date("1980-01-01T00:00:00Z");

const out = process.argv[2];
if (!out) {
  console.error("Usage: node scripts/repro-zip.mjs <output.zip>");
  process.exit(1);
}

const INPUTS = ["manifest.json", "dist/bundle.js", "icons", "pages"];

function collect(entry) {
  const stat = fs.statSync(entry);

  if (stat.isDirectory()) {
    return fs
      .readdirSync(entry)
      .sort()
      .flatMap((f) => collect(path.join(entry, f)));
  }

  return [
    {
      full: entry,
      rel: entry.replace(/\\/g, "/"),
    },
  ];
}

fs.mkdirSync(path.dirname(out), { recursive: true });

const zip = new yazl.ZipFile();

for (const input of INPUTS) {
  for (const { full, rel } of collect(input)) {
    zip.addFile(full, rel, {
      mtime: FIXED_DATE,
      mode: 0o100644,
      compress: false,
    });
  }
}

zip.end();
zip.outputStream.pipe(fs.createWriteStream(out));
