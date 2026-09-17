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
  - Other Files
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
6. To create a clean library, stop the container, set **Allow Write Actions** to `true`, and restart it. The source can remain read-only because export only reads it. If PUID `0` is required to read restricted source files, exported files are still assigned to the configured Curated Output Owner UID/GID (`99:100` by default) with writable Unraid-friendly permissions.
7. Select **Build curated library**. Explicit keepers and ungrouped files are copied to `Recovered_Curated`. Undecided known-good matches and undecided duplicate/similar group members are skipped, and recovered originals remain unchanged.
8. Keep the original recovery set until the curated output has been backed up and manually spot-checked.

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

## AI-ready follow-up

`recovery_catalog.csv` and `recovery_catalog.jsonl`, together with the directory catalog, form the handoff for later reconstruction and AI analysis. The file catalog includes placeholder fields for:

- `ai_caption`
- `ai_people`
- `ai_objects`
- `ai_ocr_text`
- `ai_tags`
- `ai_model`
- `ai_updated_at`

This makes it possible to add a later local-AI pass for semantic categories, screenshot OCR, document subjects, face grouping, and natural-language search without changing the recovery workflow.

## Updating after source changes

Run **Start or resume scan** again. Files whose size and nanosecond modification time are unchanged retain their expensive hash and image-analysis results. Missing catalog entries are removed and new/changed files are analyzed.

## Important limitations

- Similar-image groups are candidates for human review; perceptual hashes can produce false matches.
- Recovery tools may restore partial files that pass basic container validation but still contain damaged content.
- Rule-based categories are an initial triage, not final semantic organization.
- Legacy binary Office formats receive only basic type detection in this release.
- Known-good comparison is exact-content matching. A resized, recompressed, or metadata-edited version will not be treated as an identical trusted copy; it may still appear in similar-photo review.

## Development checks

```bash
python -m unittest discover -s tests -v
docker build -t recovery-curator:local .
```

GitHub Actions runs both checks for every push and pull request.
