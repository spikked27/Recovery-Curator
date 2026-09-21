# Recovery Curator for Unraid

Recovery Curator turns a mixed file-recovery dump into a reviewable catalog and, after approval, a clean categorized library. It is deliberately conservative: the first scan mounts recovered files read-only, and no result is permanently deleted.

## What this version does

- Incremental/resumable SQLite inventory suitable for multi-terabyte sources.
- Multiple saved scans with isolated progress, decisions, selected known-good folders, hashes, and reports; switch between them from the Web UI.
- Bounded-memory directory traversal and fixed-size work batches; file counts are not loaded into RAM as giant Python lists.
- Checkpoint commits after every batch, with a safe stop button and restart from the last completed checkpoint.
- Separate, configurable concurrency limits for validation and full-file hashing to prevent HDD thrashing.
- Full BLAKE3 hashing only for files that share a byte size, avoiding unnecessary reads.
- Read-only comparison against user-selected folders beneath one mounted known-good backup root. Only reference files whose sizes occur in the recovery set are hashed.
- Exact known-good matches are identified by full content hash and omitted from curated output unless explicitly marked Keep.
- Byte-for-byte duplicate groups with a recommended keeper.
- Perceptual-hash groups for resized, recompressed, rotated, or lightly edited images.
- First-class video detection and FFprobe metadata: duration, dimensions, frame rate, codecs, and embedded creation date.
- On-demand reduced photo previews and four-frame video contact sheets cached under the active saved scan.
- Decoding/validation for common images, PDF, DOCX, XLSX, PPTX, ZIP, EML, and MSG containers.
- Separate views for zero-byte and corrupt files.
- Directory evidence inventory, including empty folders, parent relationships, filesystem timestamps, ownership, permissions, ignored system folders, and read failures.
- Zero-byte files remain in the evidence catalog as named placeholders even though they have no content to hash or export.
- Conservative filename date recognition for year-first patterns such as:
  - `IMG_20230517_142233.jpg`
  - `Screenshot_2023-05-17_14-22-33.png`
  - `2023.05.17 vacation.jpg`
- Existing valid EXIF dates take priority. Ambiguous month/day names are not guessed.
- Rule-based initial categories with confidence and an explanation:
  - Camera Photos
  - Screenshots
  - Downloads and Messages
  - Graphics and Captures
  - Likely Thumbnails
  - Uncategorized Images
  - Documents
  - Emails
  - Videos
  - Other Files
- Independent media facets for media type, origin, sensitivity, topic, people, event, and source application. A file can carry several facets instead of being forced into one category.
- A non-destructive reconstruction workspace that preserves every known-good path match, links zero-byte placeholders to possible surviving content, and generates destination proposals with confidence and reasons.
- Discovered-folder review generated from the surviving hierarchy—including empty and zero-byte-only branches—so the user can recognize names shown by the application instead of recalling them unaided.
- Saved recovery context for devices, people, events, applications, folders, and privacy rules.
- Feedback-aware proposals: recognized/private folders preserve structure, recovery-noise folders are stripped, and system/application branches are excluded.
- Empty original directories beneath recognized/private branches are preserved in the proposed tree and recreated during an accepted reconstruction export.
- Optional filename/path rules that route matching files to a user-selected destination.
- Searchable proposal review with destination overrides, confidence filtering, individual approval, and bulk approval for high-confidence files.
- Optional OpenAI-compatible local or cloud vision provider with quick setup presets and cancellable batch analysis. The provider receives only reduced previews/contact sheets and structured evidence, never filesystem access or action permissions.
- Separate AI structure interpretation for folder names, folder notes, empty-directory evidence, and free-form recovery context. It uses compact four-branch decision batches with an automatic one-branch retry if a provider exhausts its output limit. Its folder classifications and path rules require human acceptance before affecting the plan.
- Branch-aware AI work packages for use with another AI agent. Recovery Curator summarizes each top-level branch into bounded, self-contained packets with context, hierarchy, aggregate evidence, representative filenames, and a strict JSON decision contract. A complete audit dossier remains available separately and is not intended for chat upload.
- Exact duplicates share one AI classification, reducing local processing and cloud API use.
- Safety-gated reconstruction export: only accepted proposals are copied, only after a current dry run and explicit confirmation. Existing output files are never overwritten.
- Evidence-first reconstruction: original hierarchy is claimed only for known-good paths, explicitly recognized/private branches, or user-approved rules. When evidence is exhausted, files use a clearly labeled `Organized Library` fallback by type, origin, interpreted category, and date rather than an invented folder tree.
- Non-destructive curated export. Selected files are copied into category/year/month folders.
- Filename-derived dates are written with ExifTool only to the curated copy, never the recovered source.
- File and directory CSV/JSONL catalogs containing paths, filesystem evidence, hashes, dates, validation, classifications, decisions, provenance, and blank AI enrichment columns.
- Manual category overrides in the catalog; overrides are retained for unchanged files on later scans.

## Install on Unraid

1. From the Unraid terminal, install the template:

   ```bash
   mkdir -p /boot/config/plugins/dockerMan/templates-user
   curl -fsSL \
     https://raw.githubusercontent.com/spikked27/Recovery-Curator/main/unraid-template.xml \
     -o /boot/config/plugins/dockerMan/templates-user/my-recovery-curator.xml
   ```

   The template pulls the published image from `ghcr.io/spikked27/recovery-curator:latest`; no local build is required.

3. In Unraid, open **Docker > Add Container** and select **Recovery-Curator** from the template list.

4. Set **Recovered Source** to the one top-level folder containing the Hetman output. Do not scan both `/mnt/user/...` and `/mnt/diskN/...` representations of the same files.

   For a recovery set located entirely on one array disk, prefer the direct read-only path, such as `/mnt/disk3/Recovered`, rather than the `/mnt/user` view.

   Optionally set **Known-Good Root** to the common parent folder containing trusted backups. For example, if the two backups are `/mnt/user/Backups/Laptop` and `/mnt/user/Backups/Old-PC`, map `/mnt/user/Backups`. The container mounts it read-only; choose the individual folders later in the Web UI.

   Keep **Appdata**, the initial **Curated Output**, and initial **Quarantine** paths on a non-array pool so catalog checkpoints and directory creation do not cause parity writes. For a pool named `cache`, use:

   - `/mnt/cache/appdata/recovery-curator`
   - `/mnt/cache/appdata/recovery-curator/staging-output`
   - `/mnt/cache/appdata/recovery-curator/staging-quarantine`

5. Leave these initial settings unchanged:

   - Recovered Source access: **Read Only**
   - Allow Write Actions: **false**

   If recovered permissions prevent UID 99 from reading parts of the source, temporarily set **User ID / PUID** to `0`. Keep the source read-only and write actions disabled. **Curated Output Owner UID/GID** remain `99`/`100`, so later exports are normalized to normal Unraid ownership even while the scanner runs as root.

6. Apply the template and open the Web UI on port `8188`.

## Safe operating sequence

1. Open **Saved scans** in the Web UI. Use the automatically imported **Original Scan**, or create a new blank named scan. An existing `/config/catalog.sqlite3` is adopted automatically during upgrade.
2. Open **Known-good folders**. Browse below the mounted root and select each trusted backup folder for the active saved scan.
3. Start the scan. A couple of terabytes can take many hours because candidate duplicates must be read and images decoded. Later runs of the same saved scan reuse unchanged results.
4. Recovery Curator inventories the selected trusted folders after source analysis. It hashes only known-good files whose sizes occur in the recovery set, then hashes the corresponding recovery candidates and records byte-for-byte matches.
5. Review known-good matches, exact duplicate groups, similar-photo groups, date proposals, and low-confidence categories. The automatic exact-keeper action only records decisions.
6. Open **Reconstruction** and select **Full media analysis**. Existing file hashes and image analysis are reused; pending videos receive FFprobe metadata without another source inventory.
7. Review folder names the application found. Mark useful original folders, recovery-generated noise, system folders, and private branches. Add remembered devices, events, applications, people, and privacy context as it becomes recognizable.
8. Select **Apply feedback to plan**. This fast rebuild uses folder reviews, preserves recognized empty directories, strips noise levels even when nested inside recognized structure, and applies automatic path rules, manual facets, and saved AI results without repeating media enrichment.
9. Optionally choose OpenAI, Anthropic Claude, Google Gemini, OpenRouter, Ollama, LM Studio, or another OpenAI-compatible endpoint. Paste a key when required, use **Test & load models**, choose a vision-capable model from the live provider list, and save the connection. Then use **Interpret folder structure and your context** before media batches. Review each suggested folder meaning or path rule before accepting it. Cloud transmission remains opt-in.
10. Search the proposed tree, override destinations where necessary, and accept proposals individually or use the confidence threshold to accept safe proposals in bulk.
11. Generate a fresh dry run. When ready to copy accepted files, stop the container, set **Allow Write Actions** to `true`, restart it, type `EXPORT`, and run the reconstruction export. The source remains read-only and unchanged. If PUID `0` is required to read restricted source files, exported files are still assigned to the configured Curated Output Owner UID/GID (`99:100` by default).
12. Keep the original recovery set until the curated output has been backed up and manually spot-checked.

The reconstruction workspace is intentionally conservative. Its output has three evidence levels:

- **Supported structure** — known-good paths, folders you explicitly marked recognized/private, and path rules you approved.
- **Interpreted category** — user or AI classifications such as Snapchat, NASA, screenshots, events, or applications. These organize content but are not represented as recovered original hierarchy.
- **Organized fallback** — media type, deterministic origin clues, and strongest available date. Unknown recovery folders are not preserved merely because their names look plausible.

If there is insufficient evidence, leaving a file in the organized fallback is the correct outcome. It is safer than fabricating an original location.

## Clearing a scan

The dashboard includes **Clear Scan & Catalog**. The action is blocked while a scan is running and requires typing `RESET`. It clears only the active saved scan: recovery records, selected known-good folders, cached reference index, decisions, action history, and generated catalog reports. It does not delete source, backup, curated-output, or quarantine files, and it does not affect other saved scans.

Use **Saved scans** to create a blank catalog or return to an earlier scan. Switching is blocked while scanning so a background worker can never write into the wrong saved catalog.

## Performance settings

The defaults are tailored for this recovery set residing on one Unraid pool drive:

- **Analysis Workers: 1** — MIME detection, validation, metadata, and perceptual image hashing without concurrent seeks.
- **Hash Workers: 1** — one sequential full-file reader, and only for files whose byte size occurs more than once.
- **Checkpoint Batch: 64** — maximum records submitted together and the normal commit interval.
- **Photo Similarity Distance: 6** — conservative 64-bit perceptual-hash radius.

Keep both worker counts at `1` while the source remains on one drive. If the recovery data is later redistributed across several physical drives or moved to SSD storage, `2` may be appropriate. Raising these values based only on CPU core count usually makes a single HDD slower because the head must seek between concurrent files.

The similar-photo stage uses a BK-tree rather than comparing every photo against every other photo. It also retains only one union representative per perceptual-hash/aspect-ratio bucket, preventing thousands of blank thumbnails or near-identical screenshots from creating a quadratic cluster. Exact duplicate detection first groups by byte size and hashes only candidate groups. These choices avoid the quadratic comparison and unbounded-GUI-state behavior that can make desktop duplicate tools appear frozen.

The dashboard reports the current phase, completed records, throughput, and remains usable while the scan runs. **Cancel Scan** requests a clean stop between batches; starting again reuses completed inventory, metadata, and hashes.

“Resume” re-traverses the recovered-source directory so additions, removals, and changed files can be detected, but it does not repeat expensive analysis or hashing for unchanged files. If `/source` is empty, missing, or wholly unreadable, the scan fails before known-good indexing and retains the prior catalog. Windows `System Volume Information` folders are intentionally ignored. Other isolated read errors are reported as warnings: readable files continue through analysis, while unseen older catalog records are retained so an inaccessible file is never mistaken for a deleted one.

Each successful inventory also writes `directory_catalog.csv` and `directory_catalog.jsonl`. These preserve empty directories and the surviving hierarchy independently from file content. The file catalog includes nanosecond modification/change timestamps, original mode/UID/GID, and an `evidence_role` that distinguishes zero-byte placeholders from content-bearing files.

The reconstruction analysis additionally writes CSV and JSONL reports for the proposed tree, discovered-folder context, every known-good path match, file relationships, multi-valued facets, and user-supplied recovery context. These reports are generated from the saved SQLite catalog and do not modify library files.

If the dashboard reports zero recovered files while known-good folders contain files, verify the Unraid bind mount from a terminal:

```sh
docker inspect Recovery-Curator --format '{{range .Mounts}}{{println .Source "->" .Destination "(" .Mode ")"}}{{end}}'
docker exec Recovery-Curator sh -c 'find /source -type f -print -quit'
```

The first command should show the intended host recovery folder mapped to `/source` with read-only mode. The second should print one recovered file. If it prints nothing, correct the **Recovered Source** host path in the container settings before scanning again.

## Quarantine mode

Quarantine physically moves a source file, so it requires both:

- **Allow Write Actions** = `true`
- The **Recovered Source** container path changed from Read Only to Read/Write

Do not enable source write access merely to build the curated library. Quarantine is optional; retaining the original recovery dump is safer.

## Metadata policy

The program never overwrites a valid existing EXIF capture date. It proposes a filename-derived date only when the name contains an unambiguous year-first date. A time is included only when all time components are present. No timezone is invented.

During curated export, a proposal with at least 85% confidence is applied to `DateTimeOriginal`, `CreateDate`, and `ModifyDate` on the copied image. Every export and repair is recorded in the action log and catalog.

## Optional AI provider and privacy

The Reconstruction page has presets for OpenAI, Anthropic Claude, Google Gemini, OpenRouter, Ollama, LM Studio, and custom OpenAI-compatible APIs. Anthropic uses its native authentication, Messages, vision, and model-list formats; the other presets use their OpenAI-compatible interfaces. **Test & load models** verifies the currently entered settings without navigating away or saving them, then fills the model picker from the provider's live model list. Save and test failures are shown inline, so the form remains intact. Replace the example local host with the LAN address of the machine running the provider. A LAN hostname, private IP, localhost, or `.local` hostname is treated as local/private. Public endpoints cannot receive previews, folder/context evidence, or notes unless **Allow previews and context to leave my network** is explicitly enabled. Files already marked adult, intimate, or possibly sensitive require the separate sensitive-media opt-in.

You can paste an API key directly into the password field. It is stored outside SQLite in the active scan's appdata directory with owner-only file permissions, is never returned to the browser, and is not included in generated catalogs. Leaving the key field blank preserves the saved key; **Forget saved key** removes it after you save. For deployments that inject secrets into the container, **Advanced settings** still accepts an environment-variable name such as `RECOVERY_AI_API_KEY`—not the key itself. AI analysis is advisory: responses are stored as source-attributed facets and an audit record. The AI cannot move, rename, quarantine, delete, or export files. Filenames, OCR, metadata, and visible text are treated as untrusted evidence rather than model instructions.

The Unraid template includes an optional masked `RECOVERY_AI_API_KEY` variable. If the provider requires a credential, set that variable in the container and enter `RECOVERY_AI_API_KEY` as the environment-variable name on the Reconstruction page. Local providers commonly leave it empty.

Use **Ask AI to improve the plan** to send high-priority branches in compact four-branch calls. The provider must choose one short action per branch instead of writing an open-ended analysis; if a batch still ends at its output limit, Recovery Curator retries those branches individually. Returned folder classifications and automatic path rules appear in a review queue and do nothing until accepted.

Use **Generate AI work package** when you want to work with a separate AI agent. Recovery Curator produces manageable JSON packets organized by real top-level branches instead of asking a chat to ingest the complete catalog. Download the next packet, copy the supplied prompt, and attach both to the AI chat. Paste or upload the returned JSON without leaving the page; Recovery Curator validates the dossier and packet IDs, catalog fingerprint, branch coverage, exact folder paths, rule matches, and conflicts with your reviews. Import every response before applying external suggestions. The Review step can then accept a selected group and rebuild the plan once. Inspect packets before sharing because filenames, notes, captions, and paths may be private.

The **complete audit dossier** remains under Advanced options. It contains every catalog record and may be far too large for a chat or model context window; it is intended for offline inspection and specialist tools, not the normal external-AI workflow.

Use **Batch classification** to analyze uncertain photos and videos, or use the Catalog's **Ask configured AI** action for one file. The batch is cancellable, skips previously analyzed media by default, and sends only one representative from each exact-duplicate set. Requests include the recovery context saved for the active scan. Any questions returned by the provider are displayed for human review rather than silently treated as facts.

## Updating after source changes

Run **Start or resume scan** again. Files whose size and nanosecond modification time are unchanged retain their expensive hash and image-analysis results. Missing catalog entries are removed and new/changed files are analyzed.

## Important limitations

- Similar-image groups are candidates for human review; perceptual hashes can produce false matches.
- Video similarity grouping is not yet automatic; the current release provides exact hashing, FFprobe metadata, and representative contact sheets.
- Recovery tools may restore partial files that pass basic container validation but still contain damaged content.
- Rule-based categories are an initial triage, not final semantic organization.
- Legacy binary Office formats receive only basic type detection in this release.
- Known-good comparison is exact-content matching. A resized, recompressed, or metadata-edited version will not be treated as an identical trusted copy; it may still appear in similar-photo review.
- The dashboard's legacy **Build curated library** action still uses category/date output. Use the Reconstruction page's dry-run and export controls when you want the reviewed proposed tree.

## Development checks

```bash
python -m unittest discover -s tests -v
docker build -t recovery-curator:local .
```

GitHub Actions runs both checks for every push and pull request.
