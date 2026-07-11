import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourcePath = path.join(root, "src", "lib", "citationFormat.ts");
const source = fs.readFileSync(sourcePath, "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ES2020,
    target: ts.ScriptTarget.ES2020
  }
}).outputText;
const tempPath = path.join(os.tmpdir(), `monday-report-citation-format-${process.pid}.mjs`);

fs.writeFileSync(tempPath, compiled);

try {
  const { formatSourceCitation } = await import(pathToFileURL(tempPath).href);
  const cases = [
    [
      "PDF page and file",
      "PDF / p. 3 / ddr.pdf",
      formatSourceCitation("pdf", { page: 3, file_path: "uploads/ddr.pdf" })
    ],
    [
      "PDF table row",
      "PDF / p. 2 / table 1 / row 2 / ddr.pdf",
      formatSourceCitation("pdf", { page: 2, table: 1, row_start: 2, row_end: 2, file_path: "uploads/ddr.pdf" })
    ],
    [
      "CSV row span",
      "CSV / rows 1-8 / npt_events.csv",
      formatSourceCitation("csv", { row_start: 1, row_end: 8, file_path: "tables/npt_events.csv" })
    ],
    [
      "Excel workbook sheet",
      "Excel / workbook / service_quality.xlsx",
      formatSourceCitation("excel", { sheet: "workbook", file_path: "tables/service_quality.xlsx" })
    ],
    [
      "Word section",
      "Word / body / daily_summary.docx",
      formatSourceCitation("word", { section: "body", file_path: "reports/daily_summary.docx" })
    ],
    [
      "Email subject",
      "Email / subject: Monday Report lineage update / ops_update.eml",
      formatSourceCitation("email", {
        subject: "Monday Report lineage update",
        file_path: "emails/ops_update.eml"
      })
    ],
    [
      "Fallback text chunk",
      "Text / chunk 4 / ddr.txt",
      formatSourceCitation("text", { chunk: 4, file_path: "reports/ddr.txt" })
    ]
  ];
  const failures = cases.filter(([, expected, actual]) => actual !== expected);

  for (const [name, expected, actual] of cases) {
    const status = actual === expected ? "PASS" : "FAIL";
    console.log(`${status}: ${name} - ${actual}`);
  }

  if (failures.length > 0) {
    console.error(`\nCitation formatter guard failed with ${failures.length} mismatch(es).`);
    process.exitCode = 1;
  } else {
    console.log("\nCitation formatter guard passed.");
  }
} finally {
  fs.rmSync(tempPath, { force: true });
}
