# Zip Scanner

Find passwords, API keys, tokens and your own personal details in a zip file or a project folder before you upload it to GitHub.

Everything runs on your computer. Nothing is sent anywhere.

Created by Khaled 2026.

## What it does

Point it at a zip or a project folder and it shows you:

- which files contain secrets (passwords, API keys, tokens, private keys)
- which files contain your personal information (name, phone number, email, address, ID numbers, location)
- the full path and the exact line of every finding
- a **Go to file** button that opens the file at that line so you can fix it

It reads every file, including binaries and files inside other archives, so nothing is skipped because of its type or size. Anything it cannot read is listed, so you know what to check yourself.

## Requirements

- Python 3.8 or newer. There is nothing to install: it uses only the Python standard library.
- Windows is the main target. macOS and Linux are supported but less tested.
- Optional: VS Code with the `code` command on your PATH, so **Go to file** can jump to the exact line. Without it, files open in Notepad (Windows) or your default editor.
- Optional: tkinter (included with the standard Python installer for Windows), which gives you the **Choose zip** and **Choose folder** dialogs. Without it you can paste a path or drop a zip instead.

## Quick start

1. Save `zip_scanner.py` anywhere on your computer.
2. Open a terminal in that folder and run:

   ```
   python zip_scanner.py
   ```

   On Windows, use `py zip_scanner.py` if `python` is not recognised.
3. Your browser opens at `http://127.0.0.1:8765`. If that port is busy, the next free one up to 8784 is used.
4. Click **Choose zip** or **Choose folder**. The scan starts as soon as you pick.
5. Read the results, click **Go to file** on anything flagged, fix it, and scan again.

Press `Ctrl+C` in the terminal to stop the program. Its temporary files are deleted when it stops.

## Using the page

| Control | What it does |
| --- | --- |
| **Choose zip** / **Choose folder** | Opens a file dialog and starts scanning the moment you pick. |
| Path box and **Scan** | Paste a path to a zip or a folder and press Enter. Quotes from "Copy as path" are fine. |
| Drop box | Drop a `.zip` onto it. This works everywhere, but the scanner cannot know where the zip came from, so **Go to file** opens a temporary copy. Prefer **Choose zip**. |
| Your own details to look for | Words that identify you, one per line (see below). |
| Original project folder | Only for zips. Where the zip was made from, if it is not next to the zip. |

### Your own details

Type anything you do not want public, one per line: your full name, phone number, email, home address, student ID, a username.

- Upper and lower case do not matter.
- Spaces, dots, dashes and underscores between words are ignored, so "Khaled Rahman" also matches `khaled_rahman` and `KhaledRahman`.
- Phone numbers match with or without +880, the leading 0, spaces and dashes.
- Bangla digits match too.
- Words shorter than 3 characters are ignored, and words shorter than 5 characters only match as whole words.
- Matches are always shown masked.
- **Remember these on this computer** keeps them in your browser on this machine only. It is off by default.

## Reading the results

The banner at the top gives the verdict: **Do not upload this yet**, **Review before you upload**, or **No known patterns found**.

Each flagged file is a card with its name, its folder, its full path, and every finding with a line number and a masked preview. Use the severity and category buttons and the search box to narrow the list.

| Severity | Typical examples |
| --- | --- |
| Critical | private keys, AWS, GitHub, OpenAI and Stripe keys, database URLs with a password, SSH key files |
| High | other tokens and webhooks, `.env` files, key and certificate files, national ID and passport numbers, photo GPS location, card numbers, your own details, files over 100 MB, random-looking hard-coded passwords |
| Medium | ordinary hard-coded passwords, phone numbers, bank account numbers, dates of birth, your user name inside a folder path, the `.git` folder |
| Low | email addresses, public IP addresses, author names in documents, log files, folders such as `node_modules` |

Below the list you may also see:

- **Inside dependency folders**: findings inside `node_modules`, virtual environments and similar. They are not your code, so they are listed separately and not counted in the verdict.
- **Suggested .gitignore lines**: ready to copy, built from what it found.
- **Check these by eye**: files it cannot read automatically, such as pictures, scanned PDFs and encrypted PDFs.
- **Not scanned**: password-protected or damaged files, symbolic links, and anything cut off by a safety limit.

**Download report** saves the results as JSON. Matched values are masked there too.

## Go to file

| Button | What it does |
| --- | --- |
| **Go to file** | Opens the file in VS Code at the first finding (or in Notepad or your default editor). PDFs, pictures and Office files open in their normal viewer. |
| **Go to line N** | Opens the file at that exact line. |
| **Show in folder** | Selects the file in Explorer or Finder. For files inside a zip it selects the zip instead. |
| **Copy path** | Copies the full path. |

For a zip, the scanner looks for your original files next to the zip, and inside a folder named like the zip. It only uses a file when its size matches the one in the zip. Set **Original project folder** if your project lives somewhere else.

If your original is not found, **Go to file** opens a temporary copy and tells you so. Fix the file in your project folder, not the copy.

Findings stored in git history cannot be opened, because they live inside compressed `.git` data. See "If something is found" below.

## Command line

```
python zip_scanner.py <zip or folder> [-t WORD] [--source FOLDER] [--json FILE]
```

| Option | Meaning |
| --- | --- |
| `-t`, `--term` | A word of your own to look for. Repeat it for more. |
| `--source` | Original project folder, for zips. |
| `--json` | Also write the full report to a JSON file. |

Examples:

```
python zip_scanner.py C:\Users\you\Desktop\project.zip -t "Your Name" -t 01712345678
python zip_scanner.py . --json report.json
```

Exit codes: `0` nothing serious found, `1` critical or high findings, `2` the scan could not run.

Because of the exit code, you can use it as a check before pushing. Save this as `.git/hooks/pre-push` in your repository:

```
#!/bin/sh
python /path/to/zip_scanner.py . || exit 1
```

It scans the whole folder each time, so it suits small projects best.

## What it looks for

**Secrets**

- private keys (RSA, EC, OpenSSH, PGP, PuTTY)
- AWS, GitHub, GitLab, Hugging Face, OpenAI, Anthropic, Stripe, Google, Slack, Discord, Telegram, SendGrid, Mailgun, npm, PyPI, Shopify, DigitalOcean, Azure and Kubernetes keys and tokens
- service-account JSON files
- database URLs with a password, and web or git URLs with a login inside
- JWTs, Bearer and Basic authorization headers, Docker registry logins
- hard-coded passwords and secrets (placeholders, environment lookups and code that only reads a value are ignored)

**Personal information**

- Bangladesh national ID, birth registration number, TIN, passport number, bank account number
- credit card numbers (checked with the Luhn test)
- phone numbers (Bangladesh and international), dates of birth, home address lines, ID numbers like `123-45-67890`
- your user name inside paths such as `C:\Users\YourName\...` or `/home/yourname/...`
- the name and email stored in git commits
- author names in Word, Excel, PowerPoint and PDF properties
- GPS location inside JPEG photos
- email addresses and public IP addresses
- anything you typed under "Your own details", in file contents and in file names

**Sensitive files, by name**

SSH keys, `.env` files, key and certificate files, credentials files, password lists, shell history, browser password and cookie stores, Android `local.properties` and signing files, Terraform state, Kubernetes config, password manager and wallet files, files that look like ID documents, CVs and resumes, Firebase config, database and backup files, VPN and remote desktop configs, Windows shortcuts and log files.

**GitHub readiness**

- files over 100 MB (GitHub rejects them) and over 50 MB (GitHub warns)
- the `.git` folder, which holds your full history
- folders that should not be uploaded: `node_modules`, `venv`, `__pycache__` and similar

## What it reads

- text and code in any encoding, including UTF-16 files and Bangla digits
- binary files, by pulling out their readable strings (ASCII and UTF-16), so keys inside programs are found
- zip files inside zip files, up to 8 levels deep, plus `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.gz`, `.bz2` and `.xz`
- Word, Excel, PowerPoint and OpenDocument files, including text that Word has split into pieces
- PDF text (best effort)
- git history: loose objects and pack files, so a secret you deleted in an old commit is still found
- very large files, read in chunks so that nothing is skipped and secrets that cross a chunk edge are still caught

It uses up to 8 CPU cores. Speed depends on your computer; in testing it read roughly 10 MB of source code per second per core.

## Limits

This is a pattern check. It will miss some things and flag some harmless ones, so look at each finding.

- It cannot read text drawn inside pictures, such as screenshots or photos of ID cards. Those are listed under **Check these by eye**.
- It cannot open password-protected zip files or encrypted PDFs. They are listed too.
- PDFs with unusual fonts, and scanned PDFs, may not give readable text.
- Only JPEG photos are checked for GPS location.
- Safety limits protect against zip bombs: 8 levels of nested archives, 40 GB in total, 1,000,000 files, and 60,000 findings in the list. Anything cut off is reported under **Not scanned**.

## Privacy and safety

- The scanner only listens on `127.0.0.1`, so other computers cannot reach it.
- The page needs a random token that changes every run, and the scanner checks the address and origin of every request, so other websites cannot talk to it.
- It never connects to the internet.
- Matched values are masked in the page and in the report. The text around a match is shown as it is.
- Zips you drop on the page and the temporary copies made by **Go to file** are kept in a `zipscanner-...` folder in your temp directory. It is deleted when you stop the program, and old leftovers are removed the next time you start it.

## If something is found

1. Change any real password, key or token that was exposed. Treat it as leaked even if you only deleted it from the file.
2. Remove the value from the file. Read it from an environment variable or from a `.env` file instead.
3. Add the suggested lines to `.gitignore` so those files are never uploaded.
4. If the finding says **Stored in git history**, deleting the file is not enough. Start the upload from a copy without the `.git` folder, or rewrite the history with a tool such as `git filter-repo`.
5. Scan again until the banner is clear, and check the **Check these by eye** list yourself.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| The file dialog does not appear | tkinter is missing. Paste the path into the box, drop the zip, or install tkinter for your Python. |
| The browser did not open | Open the address printed in the terminal. |
| **Go to file** opens Notepad, not VS Code | Make the `code` command work in your terminal (the Windows installer has an "Add to PATH" option; on macOS run "Shell Command: Install 'code' command in PATH" from the VS Code command palette). Then restart the scanner. |
| It says the zip is damaged | Make the zip again. |
| `python` is not recognised on Windows | Use `py zip_scanner.py`. |

## Files

- `zip_scanner.py`: the whole program, in one file.

---

Zip Scanner by Khaled 2026.
