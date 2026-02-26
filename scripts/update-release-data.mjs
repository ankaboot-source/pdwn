import { mkdir, writeFile } from "node:fs/promises";

const [owner, repo] = (process.env.GITHUB_REPOSITORY || "").split("/");
const outputPath = process.env.RELEASE_JSON_PATH || "website/data/release.json";

async function getLatestRelease() {
  if (!owner || !repo) {
    return {
      version: "dev",
      publishedAt: null,
      htmlUrl: null,
      body: "No release data available in this environment.",
      assets: [],
    };
  }

  const token = process.env.GITHUB_TOKEN;
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/releases/latest`, {
    headers: {
      Accept: "application/vnd.github+json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!res.ok) {
    return {
      version: "dev",
      publishedAt: null,
      htmlUrl: null,
      body: `Unable to fetch latest release (${res.status}).`,
      assets: [],
    };
  }

  const data = await res.json();
  return {
    version: data.tag_name,
    name: data.name,
    publishedAt: data.published_at,
    htmlUrl: data.html_url,
    body: data.body || "",
    assets: (data.assets || []).map((a) => ({
      name: a.name,
      downloadUrl: a.browser_download_url,
      size: a.size,
    })),
  };
}

const payload = await getLatestRelease();
await mkdir(outputPath.replace(/\/[^/]*$/, ""), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
console.log(`release metadata written to ${outputPath}`);
