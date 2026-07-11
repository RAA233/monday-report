export function formatSourceCitation(locatorType: string, locator: Record<string, unknown>): string {
  const normalizedType = locatorType.toLowerCase();
  const label = sourceTypeLabel(normalizedType);
  const fileName = fileNameFromLocator(locator);
  const parts: string[] = [label];

  if (normalizedType === "pdf") {
    const page = numberValue(locator.page);
    parts.push(page ? `p. ${page}` : "page unknown");
    const table = numberValue(locator.table);
    const rowStart = numberValue(locator.row_start);
    const rowEnd = numberValue(locator.row_end);
    if (table) {
      parts.push(`table ${table}`);
    }
    if (rowStart && rowEnd && rowEnd !== rowStart) {
      parts.push(`rows ${rowStart}-${rowEnd}`);
    } else if (rowStart) {
      parts.push(`row ${rowStart}`);
    }
  } else if (normalizedType === "csv") {
    const rowStart = numberValue(locator.row_start);
    const rowEnd = numberValue(locator.row_end);
    if (rowStart && rowEnd && rowEnd !== rowStart) {
      parts.push(`rows ${rowStart}-${rowEnd}`);
    } else if (rowStart) {
      parts.push(`row ${rowStart}`);
    }
  } else if (normalizedType === "excel") {
    const sheet = stringValue(locator.sheet);
    if (sheet) {
      parts.push(sheet);
    }
  } else if (normalizedType === "word") {
    const section = stringValue(locator.section);
    if (section) {
      parts.push(section);
    }
  } else if (normalizedType === "email") {
    const subject = stringValue(locator.subject);
    parts.push(subject ? `subject: ${subject}` : "body");
  } else {
    const chunk = numberValue(locator.chunk);
    if (chunk) {
      parts.push(`chunk ${chunk}`);
    }
  }

  if (fileName) {
    parts.push(fileName);
  }

  return parts.join(" / ");
}

function sourceTypeLabel(locatorType: string): string {
  const labels: Record<string, string> = {
    csv: "CSV",
    email: "Email",
    excel: "Excel",
    pdf: "PDF",
    text: "Text",
    word: "Word"
  };
  return labels[locatorType] ?? locatorType.toUpperCase();
}

function fileNameFromLocator(locator: Record<string, unknown>): string | null {
  const filePath = stringValue(locator.file_path);
  if (!filePath) {
    return null;
  }
  const parts = filePath.replace(/\\/g, "/").split("/").filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : null;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
