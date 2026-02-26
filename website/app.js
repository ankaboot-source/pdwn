function bytesToHuman(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "-";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let n = bytes;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function pickDownloadAssets(assets) {
  const preferred = ["AppImage", ".msi", ".exe", ".dmg", ".deb", ".rpm"];
  return assets
    .filter((asset) => preferred.some((token) => asset.name.includes(token)))
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function loadRelease() {
  const metaEl = document.querySelector("#release-meta");
  const notesEl = document.querySelector("#release-notes");
  const listEl = document.querySelector("#download-list");
  const cta = document.querySelector("#download-latest");

  try {
    const res = await fetch("./data/release.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`metadata fetch failed (${res.status})`);
    const release = await res.json();

    const when = release.publishedAt
      ? new Date(release.publishedAt).toLocaleDateString()
      : "not published yet";
    metaEl.textContent = `Version ${release.version || "dev"} · published ${when}`;
    notesEl.textContent =
      (release.body || "No release notes yet.").trim() || "No release notes yet.";

    const assets = pickDownloadAssets(release.assets || []);
    listEl.innerHTML = "";
    if (assets.length === 0) {
      listEl.textContent = "No downloadable assets detected yet.";
    } else {
      for (const asset of assets) {
        const a = document.createElement("a");
        a.className = "download-item";
        a.href = asset.downloadUrl;
        a.target = "_blank";
        a.rel = "noreferrer";
        a.textContent = `${asset.name} (${bytesToHuman(asset.size)})`;
        listEl.append(a);
      }
      cta.href = assets[0].downloadUrl;
    }
  } catch (err) {
    metaEl.textContent = "Release metadata unavailable.";
    notesEl.textContent = String(err);
    listEl.textContent = "Could not load downloadable assets.";
  }
}

loadRelease();
