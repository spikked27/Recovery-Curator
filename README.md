# Recovery Curator for Unraid

Recovery Curator turns a mixed file-recovery dump into a reviewable catalog and, after approval, a clean categorized library. It is deliberately conservative: the first scan mounts recovered files read-only, and no result is permanently deleted.

## What this version does

- Incremental/resumable SQLite inventory suitable for multi-terabyte sources.
- Bounded-memory directory traversal and fixed-size work batches; file counts are not loaded into RAM as giant Python lists.
- Checkpoint commits after every batch, with a safe stop button and restart from the last completed checkpoint.
- Separate, configurable concurrency limits for validation and full-file hashing to prevent HDD thrashing.
- Full BLAKE3 hashing only for files that share a byte size, avoiding unnecessary reads.
- Byte-for-byte duplicate groups with a recommended keeper.
- Perceptual-hash groups for resized, recompressed, rotated, or lightly edited images.
- Decoding/validation for common images, PDF, DOCX, XLSX, PPTX, ZIP, EML, and MSG containers.
- Separate views for zero-byte and corrupt files.
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
- CSV and JSONL catalogs containing hashes, dates, validation, classifications, decisions, provenance, and blank AI enrichment columns.
- Manual category overrides in the catalog; overrides are retained for unchanged files on later scans.

## Install on Unraid

1. Download and extract this bundle somewhere persistent on the server, for example:

   `/mnt/user/appdata/recovery-curator-build`

2. Open the Unraid terminal, change into the extracted directory, and run:

   ```bash
   chmod +x install-unraid.sh
   ./install-unraid.sh
   ```

3. In Unraid, open **Docker > Add Container** and select **Recovery-Curator** from the template list.

4. Set **Recovered Source** to the one top-level folder containing the Hetman output. Do not scan both `/mnt/user/...` and `/mnt/diskN/...` representations of the same files.

5. Leave these initial settings unchanged:

   - Recovered Source access: **Read Only**
   - Allow Write Actions: **false**

6. Apply the template and open the Web UI on port `8188`.

## Safe operating sequence

1. Start the first scan. A couple of terabytes can take many hours because candidate duplicates must be read and images decoded. The database lives in appdata, so later scans reuse unchanged results.
2. Review exact duplicate groups. The automatic exact-keeper action only records decisions.
3. Review similar-photo groups manually. Similar does not mean interchangeable.
4. Review date proposals and low-confidence categories in the catalog.
5. To create a clean library, stop the container, set **Allow Write Actions** to `true`, and restart it. The source can remain read-only because export only reads it.
6. Select **Build curated library**. Explicit keepers and files that are not members of any duplicate/similar group are copied to `Recovered_Curated`. Undecided grouped files are skipped for safety, and recovered originals remain unchanged.
7. Keep the original recovery set until the curated output has been backed up and manually spot-checked.

## Performance settings

The defaults are tailored for this recovery set residing on one Unraid pool drive:

- **Analysis Workers: 1** — MIME detection, validation, metadata, and perceptual image hashing without concurrent seeks.
- **Hash Workers: 1** — one sequential full-file reader, and only for files whose byte size occurs more than once.
- **Checkpoint Batch: 64** — maximum records submitted together and the normal commit interval.
- **Photo Similarity Distance: 6** — conservative 64-bit perceptual-hash radius.

Keep both worker counts at `1` while the source remains on one drive. If the recovery data is later redistributed across several physical drives or moved to SSD storage, `2` may be appropriate. Raising these values based only on CPU core count usually makes a single HDD slower because the head must seek between concurrent files.

The similar-photo stage uses a BK-tree rather than comparing every photo against every other photo. It also retains only one union representative per perceptual-hash/aspect-ratio bucket, preventing thousands of blank thumbnails or near-identical screenshots from creating a quadratic cluster. Exact duplicate detection first groups by byte size and hashes only candidate groups. These choices avoid the quadratic comparison and unbounded-GUI-state behavior that can make desktop duplicate tools appear frozen.

The dashboard reports the current phase, completed records, throughput, and remains usable while the scan runs. **Stop after checkpoint** requests a clean stop between batches; starting again reuses completed inventory, metadata, and hashes.

## Quarantine mode

Quarantine physically moves a source file, so it requires both:

- **Allow Write Actions** = `true`
- The **Recovered Source** container path changed from Read Only to Read/Write

Do not enable source write access merely to build the curated library. Quarantine is optional; retaining the original recovery dump is safer.

## Metadata policy

The program never overwrites a valid existing EXIF capture date. It proposes a filename-derived date only when the name contains an unambiguous year-first date. A time is included only when all time components are present. No timezone is invented.

During curated export, a proposal with at least 85% confidence is applied to `DateTimeOriginal`, `CreateDate`, and `ModifyDate` on the copied image. Every export and repair is recorded in the action log and catalog.

## AI-ready follow-up

`recovery_catalog.csv` and `recovery_catalog.jsonl` include placeholder fields for:

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
- The local image is named `recovery-curator:local`; rerun `install-unraid.sh` after replacing the source bundle with an updated version.

## Development checks

```bash
python -m unittest discover -s tests -v
docker build -t recovery-curator:local .
```

GitHub Actions runs both checks for every push and pull request.
