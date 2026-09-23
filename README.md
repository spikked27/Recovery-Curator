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
- Exact known-good matches are identified by full content hash and omitted from the sanitation workflow's review library.
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
- A sanitation-first curation workflow that does not claim to reconstruct the owner's original folder tree.
- Automatic omission of zero-byte placeholders, exact known-good copies, rejected/unreadable entries, and redundant byte-identical duplicates from the review library.
- Conservative review folders by media type, broad origin/collection clues, and the strongest available date evidence. Damaged non-empty files are retained under `Needs Attention`.
- Space-efficient export: unchanged files are hardlinked when source and output are on the same filesystem; files requiring repairs use independent reflink clones when supported.
- Zero-byte names and timestamps remain evidence. A strong relationship can supply a missing date to an independent copy, but placeholders are never exported as content.
- Saved recovery context for devices, people, events, applications, folders, and privacy rules.
- Optional OpenAI-compatible local or cloud vision provider with quick setup presets and cancellable batch analysis. The provider receives only reduced previews/contact sheets and structured evidence, never filesystem access or action permissions.
- An in-app AI conversation that receives bounded catalog summaries, representative filenames, and the context you provide. It can request safe read-only searches across the complete catalog before answering, so useful patterns do not need to appear in its current sample window.
- Reusable selectors support filename/path contains, starts-with, ends-with, equality, lists, and small `all`/`any` combinations. One proposal can set collection, origin, and sensitivity together instead of consuming a separate rule for each label or account name.
- AI proposals show their exact selector, estimated reach, representative matches, validation result, and reason before one confirmation. Applied rules have visible history and safe undo. They label the catalog only; the model cannot reconstruct folders, delete content, edit metadata, or run an export.
- Exact duplicates share one AI classification, reducing local processing and cloud API use.
- Safety-gated build based on a current preview and explicit `CURATE` confirmation. Existing output files are never overwritten.
- Filename-derived dates are written with ExifTool only to an independent reflink/copy, never to the recovered source or a hardlink.
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

2. In Unraid, open **Docker > Add Container** and select **Recovery-Curator** from the template list.

3. Set **Recovered Source** to the one top-level folder containing the Hetman output. Do not scan both `/mnt/user/...` and `/mnt/diskN/...` representations of the same files.

   For a recovery set located entirely on one array disk, prefer the direct read-only path, such as `/mnt/disk3/Recovered`, rather than the `/mnt/user` view.

   Optionally set **Known-Good Root** to the common parent folder containing trusted backups. For example, if the two backups are `/mnt/user/Backups/Laptop` and `/mnt/user/Backups/Old-PC`, map `/mnt/user/Backups`. The container mounts it read-only; choose the individual folders later in the Web UI.

   Keep **Appdata** and initial **Quarantine** paths on a non-array pool so catalog checkpoints do not cause parity writes. For a pool named `cache`, use:

   - `/mnt/cache/appdata/recovery-curator`
   - `/mnt/cache/appdata/recovery-curator/staging-quarantine`

   To let unchanged files use no additional data space, map **Curated Output** to a separate folder on the same direct disk/filesystem as the recovered source. For example, use `/mnt/disk3/Recovery-Curated` with a source at `/mnt/disk3/Recovered`. Never place the output inside the source. A `/mnt/cache` output cannot hardlink files from `/mnt/disk3`; those files require a reflink or an explicitly permitted full copy.

4. Leave these initial settings unchanged:

   - Recovered Source access: **Read Only**
   - Allow Write Actions: **false**

   If recovered permissions prevent UID 99 from reading parts of the source, temporarily set **User ID / PUID** to `0`. Keep the source read-only and write actions disabled. Hardlinks necessarily retain the source inode's owner, permissions, and timestamps. Independent repaired files and generated reports can use the configured Curated Output Owner UID/GID.

5. Apply the template and open the Web UI on port `8188`.

## Safe operating sequence

1. Open **Saved scans** in the Web UI. Use the automatically imported **Original Scan**, or create a new blank named scan. An existing `/config/catalog.sqlite3` is adopted automatically during upgrade.
2. Open **Known-good folders**. Browse below the mounted root and select each trusted backup folder for the active saved scan.
3. Start the scan. A couple of terabytes can take many hours because candidate duplicates must be read and images decoded. Later runs of the same saved scan reuse unchanged results.
4. Recovery Curator inventories the selected trusted folders after source analysis. It hashes only known-good files whose sizes occur in the recovery set, then hashes the corresponding recovery candidates and records byte-for-byte matches.
5. Open **Curate** and run **Analyze for curation**. Existing hashes and media analysis are reused; the app links zero-byte evidence, refreshes known-good matches, and prepares the sanitation plan.
6. Optionally use the AI conversation. Explain broad clues such as “files containing `Snapchat-` are my saved snaps.” The assistant may ask a question or propose a small number of reusable labels. Inspect the match count and apply only rules that make sense.
7. Generate the preview. Check the omission counts, repair counts, category summary, and whether source/output can use hardlinks. This is the complete decision point; individual file approval is not required.
8. When ready, set **Allow Write Actions** to `true`, restart the container, generate a fresh preview, type `CURATE`, and build the review library. If independent files cannot be reflinked, a full-copy fallback is used only when you explicitly enable it.
9. Review the resulting folders with normal file-management or media tools. Recovery Curator is not intended to become a second manual-review application.
10. Keep the original recovery set until the curated output and its manifest have been backed up and spot-checked.

The review library deliberately avoids reconstructing an original hierarchy that the evidence cannot support. It uses broad, transparent groupings such as media type, source clue, private review, damaged content, and strongest available date. The human owner can reorganize the smaller, sanitized library later without the program presenting guesses as recovered fact.

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

The curation analysis additionally writes CSV and JSONL catalogs containing known-good matches, file relationships, multi-valued facets, user context, and sanitation results. These reports are generated from the saved SQLite catalog and do not modify source files.

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

The scanner records valid EXIF capture dates, timezone offsets, camera/lens/software fields, altitude, and GPS coordinates when they exist. The program never overwrites a valid existing EXIF capture date. It proposes a filename-derived date only when the name contains an unambiguous year-first date. A time is included only when all time components are present. No timezone is invented.

Unchanged files may be hardlinked, so Recovery Curator never changes metadata, ownership, or permissions on those output entries: doing so would also change the recovered source inode. A photo that needs a high-confidence filename date is first made independent with a reflink (or an explicitly allowed copy), then ExifTool may set `DateTimeOriginal`, `CreateDate`, and `ModifyDate`. A strongly related zero-byte placeholder may supply a plausible older filesystem modification time when the evidence agrees; that repair is also applied only to an independent file. Every build and repair is recorded in the action log and catalog.

## Optional AI provider and privacy

The AI connection settings have presets for OpenAI, Anthropic Claude, Google Gemini, OpenRouter, Ollama, LM Studio, and custom OpenAI-compatible APIs. Anthropic uses its native authentication, Messages, vision, and model-list formats; the other presets use their OpenAI-compatible interfaces. **Test & load models** verifies the currently entered settings without navigating away or saving them, then fills the model picker from the provider's live model list. Save and test failures are shown inline, so the form remains intact. Replace an example local host with the LAN address of the machine running the provider. A LAN hostname, private IP, localhost, or `.local` hostname is treated as local/private. Public endpoints cannot receive catalog context or previews unless **Allow previews and context to leave my network** is explicitly enabled. Files already marked adult, intimate, or possibly sensitive require the separate sensitive-media opt-in before direct media analysis.

You can paste an API key directly into the password field. It is stored outside SQLite in the active scan's appdata directory with owner-only file permissions, is never returned to the browser, and is not included in generated catalogs. Leaving the key field blank preserves the saved key; **Forget saved key** removes it after you save. For deployments that inject secrets into the container, **Advanced settings** still accepts an environment-variable name such as `RECOVERY_AI_API_KEY`—not the key itself. AI analysis is advisory: responses are stored as source-attributed facets and an audit record. The AI cannot move, rename, quarantine, delete, or export files. Filenames, OCR, metadata, and visible text are treated as untrusted evidence rather than model instructions.

The Unraid template includes an optional masked `RECOVERY_AI_API_KEY` variable. If the provider requires a credential, set that variable in the container and enter `RECOVERY_AI_API_KEY` as the environment-variable name in Advanced AI settings. Local providers commonly leave it empty.

The normal AI workflow is a conversation inside **Curate**. Each turn begins with a bounded statistical summary, the context you entered, metadata coverage, capture-year distributions, camera models, neighborhood-scale GPS clusters, and a rotating sample of representative filenames. Exact coordinates stay in the local catalog; coordinates included in conversational context are rounded to 0.01-degree cells. When the initial context is insufficient, the assistant can ask Recovery Curator to run bounded read-only searches across the complete catalog by filename/path, media type, capture date, camera metadata, or rounded GPS area. It receives counts, representative matches, media types, dates, locations, and existing origins before it replies. Search selectors are locally validated and cannot execute arbitrary SQL or filesystem operations.

The assistant can then stage reusable rules such as “filename starts with `~`” or “path contains `SnapSave`.” A single suggestion may set collection, origin, and sensitivity together. The confirmation queue shows its complete selector, actions, affected-file count, examples, confidence, and reason. Unsupported or zero-match suggestions remain visible with their validation errors instead of disappearing. Applied, dismissed, invalid, and undone rules have separate histories; newer overlapping AI rules must be undone first so restoration remains deterministic. No proposal affects the catalog until **Apply suggestion** is selected, and any labeling change invalidates the prior build preview. The AI cannot create original-folder claims, choose deletions, suppress known-good safeguards, change metadata, or run the build.

The Curate page reuses the last calculated overview instead of rerunning full-catalog deduplication during every conversation or rule action. Label changes immediately revoke build authorization and mark the visible overview stale; select **Generate current build preview** when the conversation is finished to refresh destinations, collision checks, and the build token.

Legacy work packages, packet-response import, the full audit dossier, and reconstruction experiments remain available under Advanced options for compatibility and specialist inspection. They are not part of the recommended sanitation workflow and may expose private paths, filenames, notes, or captions if shared externally.

Use **Batch classification** to analyze uncertain photos and videos, or use the Catalog's **Ask configured AI** action for one file. The batch is cancellable, skips previously analyzed media by default, and sends only one representative from each exact-duplicate set. Requests include the recovery context saved for the active scan. Any questions returned by the provider are displayed for human review rather than silently treated as facts.

## Updating after source changes

Run **Start or resume scan** again. Files whose size and nanosecond modification time are unchanged retain their expensive hash and current image-analysis results. When an update adds new metadata extraction, existing photos are revisited once to populate those fields without discarding their hashes. Missing catalog entries are removed and new/changed files are analyzed.

## Important limitations

- Similar-image groups are candidates for human review; perceptual hashes can produce false matches.
- Video similarity grouping is not yet automatic; the current release provides exact hashing, FFprobe metadata, and representative contact sheets.
- Recovery tools may restore partial files that pass basic container validation but still contain damaged content.
- Rule-based categories are an initial triage, not final semantic organization.
- Legacy binary Office formats receive only basic type detection in this release.
- Known-good comparison is exact-content matching. A resized, recompressed, or metadata-edited version will not be treated as an identical trusted copy; it may still appear in similar-photo review.
- Hardlinks require source and output to be on the same filesystem and may also be limited by host permissions. Reflink support depends on the filesystem. Cross-filesystem output can therefore require full additional storage, and Recovery Curator will not do that without an explicit per-build opt-in.
- Similar-looking files are deliberately retained. Only byte-identical duplicates are collapsed automatically.

## Development checks

```bash
python -m unittest discover -s tests -v
docker build -t recovery-curator:local .
```

GitHub Actions runs both checks for every push and pull request.
