import re
from pathlib import Path

REFERENCES_DIR = Path(__file__).resolve().parent.parent / "references"

PITFALLS_FILE = REFERENCES_DIR / "verification-pitfalls.md"
CROSS_REF_FILES = [
    "review-methodology.md",
    "security-hardening-checklist.md",
    "known-bug-patterns.md",
    "verification-pitfalls.md",
]

# Bounded to 1-2 digits so a 3+-digit token (e.g. a PR number like #2898) is
# never partially matched.
HASH_REF_RE = re.compile(r"(?<!&)#\d{1,2}(?!\d)")  # (?<!&): skip HTML entities like `&#91;`
PAREN_REF_RE = re.compile(r"pitfall (\d+)\)")

VERSION_LINE_RE = re.compile(r"_Version:\s*(\d+)\s*patterns")
HEADING_RE = re.compile(r"^## The (\d+) pitfall patterns", re.MULTILINE)
ENTRY_RE = re.compile(r"^\d+\.\s", re.MULTILINE)


def test_pitfalls_version_and_heading_match_entry_count():
    """DT-a: version line, section heading, and numbered entries all agree."""
    text = PITFALLS_FILE.read_text()

    version_match = VERSION_LINE_RE.search(text)
    assert version_match, "_Version: N patterns line not found"
    version_n = int(version_match.group(1))

    heading_match = HEADING_RE.search(text)
    assert heading_match, "## The N pitfall patterns heading not found"
    heading_n = int(heading_match.group(1))

    entry_count = len(ENTRY_RE.findall(text))

    assert version_n == heading_n == entry_count


def test_pitfall_cross_references_resolve():
    """DT-b: every #N and (pitfall N) cross-reference stays within range."""
    pitfalls_text = PITFALLS_FILE.read_text()
    max_pitfall = max(int(n) for n in re.findall(r"^(\d+)\.\s", pitfalls_text, re.MULTILINE))

    referenced = set()
    for name in CROSS_REF_FILES:
        text = (REFERENCES_DIR / name).read_text()
        for m in HASH_REF_RE.findall(text):
            referenced.add(int(m.lstrip("#")))
        for m in PAREN_REF_RE.findall(text):
            referenced.add(int(m))

    assert referenced, "expected at least one pitfall cross-reference"
    for n in referenced:
        assert 1 <= n <= max_pitfall


def _extract_compliance_trace_labels(text):
    """Pull the bullet labels out of a '## Compliance trace' block.

    Top-level bullets are labelled by the text up to their trailing ':'
    (e.g. 'Head:', 'Tests run:'). The 'Refs read:' sub-bullets are labelled
    by the reference file name they attest to (e.g. 'review-methodology.md').
    """
    block_match = re.search(r"## Compliance trace\b(.*?)(?=\n## |\Z)", text, re.DOTALL)
    assert block_match, "## Compliance trace block not found"
    block = block_match.group(1)

    labels = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        content = stripped[2:].strip()

        file_match = re.match(r"([\w.-]+\.md)\s", content)
        if file_match:
            labels.append(file_match.group(1))
            continue

        label_match = re.match(r"(.+?:)", content)
        if label_match:
            labels.append(label_match.group(1))

    return labels


def test_compliance_trace_labels_match_template():
    """DT-c: every Compliance-trace label in output-format.md appears in review-template.md."""
    output_format_text = (REFERENCES_DIR / "output-format.md").read_text()
    template_text = (REFERENCES_DIR / "review-template.md").read_text()

    required_labels = _extract_compliance_trace_labels(output_format_text)
    assert required_labels, "expected at least one Compliance-trace label"

    for label in required_labels:
        assert label in template_text
