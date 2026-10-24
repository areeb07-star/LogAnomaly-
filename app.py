from __future__ import annotations

import csv
import difflib
import hashlib
import io

import matplotlib.pyplot as plt
import streamlit as st

from analysis_engine import analyze_logs, parse_uploaded_text

st.set_page_config(page_title="LogAnomaly · Universal Log Monitor", page_icon="🛡️", layout="wide")

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
TEXT_EXTENSIONS = {".txt", ".log", ".out", ".csv", ".json", ".jsonl", ".ndjson"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}

if "theme_mode" not in st.session_state:
    st.session_state["theme_mode"] = "Dark"
THEME = st.session_state["theme_mode"]


def merge_ocr_rows(rows: list[tuple[float, float, str, float, float]]) -> list[str]:
    """Merge OCR text boxes that belong to the same visible horizontal line."""
    if not rows:
        return []
    heights = sorted(max(float(row[4]), 1.0) for row in rows)
    median_height = heights[len(heights) // 2]
    tolerance = max(6.0, median_height * 0.7)
    groups: list[dict[str, object]] = []
    for y, x, text, confidence, _ in sorted(rows, key=lambda row: (row[0], row[1])):
        matching = None
        for group in reversed(groups[-3:]):
            if abs(float(group["y"]) - y) <= tolerance:
                matching = group
                break
        if matching is None:
            matching = {"y": y, "items": []}
            groups.append(matching)
        items = matching["items"]
        items.append((x, text, confidence))

    lines: list[str] = []
    seen: set[str] = set()
    for group in sorted(groups, key=lambda item: float(item["y"])):
        items = sorted(group["items"], key=lambda item: item[0])
        line = " ".join(str(item[1]).strip() for item in items if str(item[1]).strip())
        compact = "".join(char.lower() for char in line if char.isalnum())
        if line and compact and compact not in seen:
            seen.add(compact)
            lines.append(line)
    return lines


@st.cache_resource(show_spinner=False)
def rapid_ocr_reader():
    from rapidocr import RapidOCR
    return RapidOCR()


@st.cache_data(show_spinner=False)
def read_screenshot(image_bytes: bytes) -> tuple[str, str]:
    """Read visible text locally and return clean, distinct lines."""
    try:
        from PIL import Image, ImageEnhance, ImageOps
        with Image.open(io.BytesIO(image_bytes)) as opened:
            image = opened.convert("RGB")
        # Improve small, low-contrast screenshots for OCR while keeping the
        # original upload untouched for the preview shown to the user.
        ocr_image = ImageOps.autocontrast(ImageOps.grayscale(image))
        if min(ocr_image.size) < 1200:
            scale = min(2.0, 1200 / max(min(ocr_image.size), 1))
            ocr_image = ocr_image.resize((int(ocr_image.width * scale), int(ocr_image.height * scale)))
        ocr_image = ImageEnhance.Contrast(ocr_image).enhance(1.15).convert("RGB")

        # RapidOCR detects complete text lines and their positions, which is
        # usually more reliable for log screenshots than OCRing a full page as
        # one paragraph. Tesseract remains as a fallback for difficult images.
        try:
            import numpy as np
            reader = rapid_ocr_reader()
            detected = reader(np.asarray(ocr_image))
            texts = getattr(detected, "txts", None) or []
            boxes = getattr(detected, "boxes", None)
            scores = getattr(detected, "scores", None) or []
            rows: list[tuple[float, float, str, float, float]] = []
            for index, value in enumerate(texts):
                clean = " ".join(str(value).split()).strip()
                confidence = float(scores[index]) if index < len(scores) else 0.0
                if not clean or confidence < 0.35:
                    continue
                box = boxes[index] if boxes is not None and index < len(boxes) else None
                if box is None:
                    y, x, height = float(index), 0.0, 18.0
                else:
                    y = sum(float(point[1]) for point in box) / max(len(box), 1)
                    x = sum(float(point[0]) for point in box) / max(len(box), 1)
                    height = max(float(point[1]) for point in box) - min(float(point[1]) for point in box)
                rows.append((y, x, clean, confidence, height))
            cleaned_rows = merge_ocr_rows(rows)
            if cleaned_rows:
                return "\n".join(cleaned_rows), ""
        except Exception:
            pass

        try:
            import pytesseract
            data = pytesseract.image_to_data(ocr_image, config="--psm 6", output_type=pytesseract.Output.DICT)
            grouped: dict[tuple[int, int, int], list[tuple[int, str]]] = {}
            for index, raw in enumerate(data.get("text", [])):
                token = str(raw).strip()
                try:
                    confidence = float(data["conf"][index])
                except (TypeError, ValueError, IndexError):
                    confidence = 0.0
                if not token or confidence < 25:
                    continue
                key = (int(data["block_num"][index]), int(data["par_num"][index]), int(data["line_num"][index]))
                grouped.setdefault(key, []).append((int(data["left"][index]), token))
            text = "\n".join(" ".join(token for _, token in sorted(words)) for words in grouped.values()).strip()
            if not text:
                text = pytesseract.image_to_string(ocr_image, config="--psm 6").strip()
            if text:
                lines = []
                seen = set()
                for line in text.splitlines():
                    clean = " ".join(line.split()).strip()
                    compact = "".join(char.lower() for char in clean if char.isalnum())
                    if clean and compact not in seen:
                        seen.add(compact)
                        lines.append(clean)
                return "\n".join(lines), ""
        except Exception:
            # Tesseract is optional; most users will use the packaged ONNX fallback.
            pass

        try:
            import numpy as np
            reader = rapid_ocr_reader()
            found: list[tuple[float, float, str, float]] = []

            def add_detections(result, y_offset: int = 0) -> None:
                texts = getattr(result, "txts", None) or []
                boxes = getattr(result, "boxes", None)
                scores = getattr(result, "scores", None) or []
                for index, detected_text in enumerate(texts):
                    if not str(detected_text).strip():
                        continue
                    box = boxes[index] if boxes is not None and len(boxes) > index else None
                    if box is None:
                        y, x = float(index), 0.0
                    else:
                        y = y_offset + sum(float(point[1]) for point in box) / max(len(box), 1)
                        x = sum(float(point[0]) for point in box) / max(len(box), 1)
                    confidence = float(scores[index]) if scores is not None and len(scores) > index else 0.0
                    found.append((y, x, str(detected_text).strip(), confidence))

            add_detections(reader(np.asarray(ocr_image)))
            # Full screenshots can have very small log text. If the whole-image
            # pass finds few rows, scan overlapping horizontal strips for recall.
            if ocr_image.height >= 260 and len(found) < max(3, ocr_image.height // 220):
                strip_height = max(160, min(280, ocr_image.height // 4))
                stride = max(100, int(strip_height * 0.72))
                for top in range(0, ocr_image.height, stride):
                    bottom = min(ocr_image.height, top + strip_height)
                    if bottom - top < 80:
                        continue
                    strip_results = reader(np.asarray(ocr_image.crop((0, top, ocr_image.width, bottom))))
                    add_detections(strip_results, top)

            found.sort(key=lambda row: (row[0], row[1]))
            unique: list[tuple[float, float, str, float]] = []
            for candidate in found:
                compact = "".join(char.lower() for char in candidate[2] if char.isalnum())
                duplicate_index = None
                for index, prior in enumerate(unique):
                    prior_compact = "".join(char.lower() for char in prior[2] if char.isalnum())
                    if compact and prior_compact and difflib.SequenceMatcher(None, compact, prior_compact).ratio() >= 0.94:
                        duplicate_index = index
                        break
                if duplicate_index is None:
                    unique.append(candidate)
                elif candidate[3] > unique[duplicate_index][3]:
                    unique[duplicate_index] = candidate
            unique.sort(key=lambda row: (row[0], row[1]))
            text = "\n".join(row[2] for row in unique)
            if text:
                return text, ""
            return "", "No readable text was found. Try a sharper screenshot or paste the log text instead."
        except ImportError:
            return "", "OCR packages are missing. Run `pip install -r requirements.txt`, then restart the app."
        except Exception as exc:
            return "", f"The screenshot was received, but local OCR could not read it: {exc}. On first use, check your internet connection so the OCR model can download, then use Retry reading files below."
    except ImportError:
        return "", "Image support is missing. Run `pip install -r requirements.txt`, then restart the app."
    except Exception as exc:
        return "", f"The screenshot was received, but it could not be opened: {exc}"


theme_css = """
<style>
    .block-container { max-width: 1240px; padding-top: 2.1rem; padding-bottom: 4rem; }
    .hero { padding: 1.5rem 1.65rem; border: 1px solid __BORDER__; border-radius: 18px;
            background: linear-gradient(115deg, __HERO1__ 0%, __HERO2__ 58%, __HERO3__ 100%); margin-bottom: 1rem; }
    .hero { margin-bottom: 1.45rem; }
    .hero h1 { margin: 0; color: __TEXT__; letter-spacing: -.04em; }
    .hero p { margin: .55rem 0 0 0; color: __MUTED__; font-size: 1.04rem; line-height: 1.55; }
    div[data-testid="stMetric"] { border: 1px solid __BORDER__; padding: 13px; border-radius: 12px; background: __CARD__; }
    div[data-testid="stFileUploader"] { border: 1px dashed __ACCENT__; border-radius: 12px; padding: .35rem; background: __CARD__; }
    [data-testid="stSidebar"] { background: __SIDEBAR__; }
    [data-testid="stAppViewContainer"], [data-testid="stHeader"] { background: __BG__; color: __TEXT__ !important; }
    [data-testid="stAppViewContainer"] h1, [data-testid="stAppViewContainer"] h2,
    [data-testid="stAppViewContainer"] h3, [data-testid="stAppViewContainer"] h4,
    [data-testid="stAppViewContainer"] p, [data-testid="stAppViewContainer"] label,
    [data-testid="stAppViewContainer"] li, [data-testid="stSidebar"] * { color: __TEXT__ !important; }
    [data-testid="stAppViewContainer"] small, [data-testid="stAppViewContainer"] .stCaption { color: __MUTED__ !important; }
    textarea, input { background: __CARD__ !important; color: __TEXT__ !important; border-color: __BORDER__ !important; }
    div[data-baseweb="select"] > div { background: __CARD__ !important; border-color: __BORDER__ !important; }
    div[data-baseweb="select"] span, div[data-baseweb="select"] input { color: __TEXT__ !important; }
    button { background: __CARD__ !important; color: __TEXT__ !important; border: 1px solid __BORDER__ !important; }
    button p, button span { color: __TEXT__ !important; }
    button[kind="primary"] { background: __ACCENT__ !important; color: #07131e !important; border-color: __ACCENT__ !important; font-weight: 700; }
    button[kind="primary"] p, button[kind="primary"] span { color: #07131e !important; }
    [data-testid="stFileUploader"] button { background: __ACCENT__ !important; color: #07131e !important; border-color: __ACCENT__ !important; }
    [data-testid="stFileUploader"] button * { color: #07131e !important; }
    button:hover { border-color: __ACCENT__ !important; filter: brightness(1.08); }
    div[data-testid="stExpander"], div[data-testid="stExpander"] details,
    div[data-testid="stExpander"] summary { background: __CARD__ !important; border-color: __BORDER__ !important; color: __TEXT__ !important; }
    div[data-testid="stExpander"] summary *, div[data-testid="stExpander"] details p,
    div[data-testid="stExpander"] details span { color: __TEXT__ !important; }
    pre, code, [data-testid="stCode"] { background: __CODE_BG__ !important; color: __CODE_TEXT__ !important; }
    .severity-badge { display: inline-block; padding: .18rem .5rem; border-radius: 999px; font-size: .72rem; font-weight: 800; letter-spacing: .04em; margin: .25rem 0 .45rem; }
    .severity-critical, .severity-error { background: __RED_BG__; color: __RED_TEXT__ !important; border: 1px solid __RED_BORDER__; }
    .severity-warning { background: __YELLOW_BG__; color: __YELLOW_TEXT__ !important; border: 1px solid __YELLOW_BORDER__; }
    .severity-info, .severity-debug, .severity-unknown { background: __BLUE_BG__; color: __BLUE_TEXT__ !important; border: 1px solid __BLUE_BORDER__; }
    .status-ok { color: __GREEN_TEXT__ !important; }
    .section-heading { display: flex; align-items: center; gap: .8rem; margin: 1.8rem 0 .75rem; }
    .section-icon { display: inline-flex; align-items: center; justify-content: center; width: 2.15rem; height: 2.15rem; border-radius: .75rem; font-size: 1.15rem; font-weight: 800; }
    .section-cyan { background: #164e63; color: #67e8f9 !important; }
    .section-violet { background: #3b2a63; color: #c4b5fd !important; }
    .section-green { background: #164e3a; color: #86efac !important; }
    .section-amber { background: #513b16; color: #fcd34d !important; }
    .section-copy { display: flex; flex-direction: column; gap: .08rem; }
    .section-kicker { color: __MUTED__ !important; font-size: .7rem; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
    .section-title { color: __TEXT__ !important; font-size: 1.25rem; font-weight: 750; letter-spacing: -.02em; }
    .step-note { margin-bottom: .7rem; line-height: 1.5; }
    .step-note, .muted-note { color: __MUTED__; font-size: .92rem; }
    .eyebrow { color: __ACCENT__; text-transform: uppercase; letter-spacing: .12em; font-size: .72rem; font-weight: 700; }
    .source-label { color: __MUTED__; font-size: .84rem; margin-bottom: .15rem; }
</style>
""".replace("__BORDER__", "#28384d" if THEME == "Dark" else "#d8e6f5").replace("__HERO1__", "#13263a" if THEME == "Dark" else "#eef6ff").replace("__HERO2__", "#172235" if THEME == "Dark" else "#f5f8ff").replace("__HERO3__", "#123a3d" if THEME == "Dark" else "#effaf8").replace("__TEXT__", "#f4f8fc" if THEME == "Dark" else "#183653").replace("__MUTED__", "#9eb1c5" if THEME == "Dark" else "#536b82").replace("__CARD__", "#101c2b" if THEME == "Dark" else "#fbfdff").replace("__CODE_BG__", "#0b1624" if THEME == "Dark" else "#f4f7fb").replace("__CODE_TEXT__", "#e7f4ff" if THEME == "Dark" else "#24364b").replace("__SIDEBAR__", "#0d1724" if THEME == "Dark" else "#f2f6fb").replace("__BG__", "#0b1320" if THEME == "Dark" else "#ffffff").replace("__ACCENT__", "#67e8f9" if THEME == "Dark" else "#1976a8").replace("__RED_BG__", "#4a1720" if THEME == "Dark" else "#fde8eb").replace("__RED_TEXT__", "#ff9eaa" if THEME == "Dark" else "#a61b2b").replace("__RED_BORDER__", "#b83245" if THEME == "Dark" else "#ef9aa5").replace("__YELLOW_BG__", "#493612" if THEME == "Dark" else "#fff4d6").replace("__YELLOW_TEXT__", "#ffd76a" if THEME == "Dark" else "#825b00").replace("__YELLOW_BORDER__", "#c99520" if THEME == "Dark" else "#e8c45c").replace("__BLUE_BG__", "#12324a" if THEME == "Dark" else "#e7f3fb").replace("__BLUE_TEXT__", "#92d7ff" if THEME == "Dark" else "#155a82").replace("__BLUE_BORDER__", "#2d86b8" if THEME == "Dark" else "#9ccce6").replace("__GREEN_TEXT__", "#8ce5ac" if THEME == "Dark" else "#18733b")
st.markdown(theme_css, unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## ◉ LogAnomaly")
    st.caption("Real-time log anomaly detector")
    st.selectbox("Appearance", ["Dark", "Light"], key="theme_mode", help="Switch appearance without clearing your work.")
    st.divider()

    st.markdown("### About")
    st.write("Upload logs or screenshots, or paste text. The app highlights unusual events and suggests safe checks.")
    st.divider()

    with st.expander("Common issues", expanded=False):
        st.markdown("""
- App and server errors
- Service failures
- Memory and disk problems
- Network and DNS issues
- Database problems
- Login and access failures
- TLS and configuration issues
""")

    with st.expander("Quick steps", expanded=False):
        st.markdown("""
1. **Add logs** — upload a file or screenshot, or paste text.
2. **Review text** — correct any OCR mistakes.
3. **Analyze** — read the findings and next checks.
""")
    st.caption("Your files stay local. Scores show review priority, not certainty.")

SAMPLE = """2026-10-24T09:10:00Z api-1 INFO Started HTTP server on port 8080
2026-10-24T09:10:04Z api-1 INFO GET /health status=200 duration_ms=4
2026-10-24T09:10:07Z api-1 WARN retrying database connection after timeout
2026-10-24T09:10:09Z api-1 ERROR connection refused to database db.internal:5432
2026-10-24T09:10:10Z kernel: Out of memory: Killed process 1842 (worker)
2026-10-24T09:10:12Z nginx ERROR upstream timed out while reading response header
2026-10-24T09:10:14Z sshd WARNING Failed password for invalid user admin from 203.0.113.12 port 49100
2026-10-24T09:10:18Z systemd INFO Started Session 18 of User deploy
2026-10-24T09:10:20Z app ERROR TLS certificate verify failed for payments.example.net
"""

st.markdown("""
<div class="hero">
  <div class="eyebrow">Real-time server log review</div>
  <h1>Find the lines worth checking.</h1>
  <p>Upload logs or a screenshot. The N-gram model finds unusual sequences, then gives clear findings and safe next checks.</p>
</div>
""", unsafe_allow_html=True)

st.info("**How it works:** LogAnomaly reads your text locally, learns common three-word sequences with an N-gram model, checks severity and system patterns, then explains what each finding may mean. It does not send your files to a hosted model.")

st.markdown('<div class="section-heading"><span class="section-icon section-cyan">↥</span><div class="section-copy"><div class="section-kicker">Step 1</div><div class="section-title">Add your logs</div></div></div>', unsafe_allow_html=True)
st.markdown('<p class="step-note">Upload text files or screenshots, or paste log lines below. Screenshot text is read automatically and remains editable.</p>', unsafe_allow_html=True)

uploaded_files = st.file_uploader(
    "Upload log files or screenshots",
    type=["txt", "log", "out", "csv", "json", "jsonl", "ndjson", "png", "jpg", "jpeg", "webp", "bmp", "tif", "tiff"],
    accept_multiple_files=True,
    help="Up to 10 MB per file. Screenshot text is extracted automatically; you can review it before analysis.",
    key="all_log_uploads",
)

# Import new uploads into the editable box once. This prevents Streamlit reruns
# from overwriting edits the user makes after OCR or text-file loading.
if uploaded_files:
    upload_signature = hashlib.sha256()
    for uploaded in uploaded_files:
        upload_signature.update(uploaded.name.encode("utf-8", errors="replace"))
        upload_signature.update(uploaded.getvalue())
    current_signature = upload_signature.hexdigest()
    if current_signature != st.session_state.get("loaded_upload_signature"):
        content_parts: list[str] = []
        errors: list[str] = []
        loaded_count = 0
        for uploaded in uploaded_files:
            extension = "." + uploaded.name.rsplit(".", 1)[-1].lower() if "." in uploaded.name else ""
            if uploaded.size > MAX_UPLOAD_BYTES:
                errors.append(f"{uploaded.name}: over the 10 MB per-file limit, so it was skipped.")
                continue
            try:
                if extension in IMAGE_EXTENSIONS:
                    with st.spinner(f"Reading screenshot: {uploaded.name}…"):
                        text, error = read_screenshot(uploaded.getvalue())
                    if error:
                        errors.append(f"{uploaded.name}: {error}")
                    if text:
                        content_parts.append(f"# --- OCR from {uploaded.name} ---\n{text}")
                        loaded_count += 1
                elif extension in TEXT_EXTENSIONS:
                    text = parse_uploaded_text(uploaded.name, uploaded.getvalue()).strip()
                    if text:
                        content_parts.append(f"# --- {uploaded.name} ---\n{text}")
                        loaded_count += 1
                else:
                    errors.append(f"{uploaded.name}: unsupported file type.")
            except Exception as exc:
                errors.append(f"{uploaded.name}: could not read file ({exc}).")

        if content_parts:
            st.session_state["log_text"] = "\n\n".join(content_parts)
            st.session_state["analysis_results"] = None
            st.session_state["upload_status"] = f"Read {loaded_count} file(s). Check the extracted text below, correct any OCR mistakes, then choose Analyze logs."
        elif errors:
            st.session_state["upload_status"] = "The file was received, but no log text could be loaded. See the note below; you do not need to upload it again."
        else:
            st.session_state["upload_status"] = "No readable text was found in the selected file(s)."
        st.session_state["upload_errors"] = errors
        st.session_state["loaded_upload_signature"] = current_signature
elif st.session_state.get("loaded_upload_signature") is not None:
    # Let a user clear the uploader and later select the same file again.
    st.session_state["loaded_upload_signature"] = None
    st.session_state["upload_status"] = ""
    st.session_state["upload_errors"] = []

if st.session_state.get("upload_status"):
    status = st.session_state["upload_status"]
    if st.session_state.get("upload_errors"):
        st.warning(status)
        for error in st.session_state["upload_errors"]:
            st.caption(error)
        if st.button("Retry reading selected files", help="Try the files already selected again. No need to upload them again."):
            st.session_state["loaded_upload_signature"] = None
            st.rerun()
    else:
        st.success(status)

with st.expander("Preview screenshot", expanded=False):
    images = [item for item in (uploaded_files or []) if ("." + item.name.rsplit(".", 1)[-1].lower()) in IMAGE_EXTENSIONS]
    if images:
        cols = st.columns(min(len(images), 3))
        for index, image_file in enumerate(images):
            with cols[index % len(cols)]:
                st.image(image_file, caption=image_file.name, width="stretch")
    else:
        st.caption("No screenshot selected.")

if uploaded_files and any(("." + item.name.rsplit(".", 1)[-1].lower()) in IMAGE_EXTENSIONS for item in uploaded_files):
    st.caption("OCR is a helpful first draft, not a perfect transcription. Always review names, timestamps, IDs, and punctuation before analyzing.")

if "log_text" not in st.session_state:
    st.session_state["log_text"] = ""

sample_col, tip_col = st.columns([1, 3])
with sample_col:
    if st.button("Load sample logs", help="Try an example containing Linux, web, authentication, database, and TLS events."):
        st.session_state["log_text"] = SAMPLE
        st.session_state["analysis_results"] = None
with tip_col:
    st.caption("Tip: You can edit the extracted text before analysis. One log event per line works best.")

log_text = st.text_area(
    "Log text",
    height=220,
    placeholder="Upload a file above or paste log lines here…",
    key="log_text",
    label_visibility="collapsed",
)

st.markdown('<div class="section-heading"><span class="section-icon section-violet">◌</span><div class="section-copy"><div class="section-kicker">Step 2</div><div class="section-title">Choose sensitivity</div></div></div>', unsafe_allow_html=True)
st.markdown('<p class="step-note">Lower scores flag more lines. The default is a good first pass.</p>', unsafe_allow_html=True)
threshold = st.slider("Flag lines at or above this score", min_value=30, max_value=95, value=60, step=5)

st.markdown('<div class="section-heading"><span class="section-icon section-green">✓</span><div class="section-copy"><div class="section-kicker">Step 3</div><div class="section-title">Analyze logs</div></div></div>', unsafe_allow_html=True)
if st.button("Analyze logs", type="primary", width="stretch"):
    lines = [line for line in log_text.splitlines() if line.strip()]
    if not lines:
        if st.session_state.get("upload_errors"):
            st.warning("There is no readable text in the editor yet. The screenshot is still selected; choose Retry reading selected files or paste the screenshot text below. You do not need to upload it again.")
        else:
            st.warning("Paste some log lines, upload a log file, or add a readable screenshot first.")
        st.session_state["analysis_results"] = None
    else:
        st.session_state["analysis_results"] = analyze_logs(lines, threshold=threshold)
        st.session_state["analysis_threshold"] = threshold

results = st.session_state.get("analysis_results")
if results:
    threshold_used = st.session_state.get("analysis_threshold", threshold)
    anomalies = [item for item in results if item["is_anomaly"]]
    critical = sum(item["severity"] == "CRITICAL" for item in results)
    st.divider()
    st.markdown('<div class="section-heading"><span class="section-icon section-amber">!</span><div class="section-copy"><div class="section-kicker">Analysis complete</div><div class="section-title">Findings</div></div></div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("Log lines checked", len(results))
    c2.metric("Worth reviewing", len(anomalies))
    c3.metric("Critical indicators", critical)
    st.caption(f"These are review priorities, not probabilities or final diagnoses. Lines at {threshold_used}+ are shown as worth checking.")

    severity_colors = {
        "CRITICAL": "#ef4444",
        "ERROR": "#f97316",
        "WARNING": "#eab308",
        "INFO": "#38bdf8",
        "DEBUG": "#94a3b8",
        "UNKNOWN": "#94a3b8",
    }
    # Keep the original vertical comparison style, but use severity colors and
    # sensible tick spacing so larger log batches remain readable.
    chart_items = results
    x = [item["line_number"] for item in chart_items]
    values = [item["score"] for item in chart_items]
    colors = [severity_colors.get(item["severity"], "#38bdf8") for item in chart_items]
    fig, ax = plt.subplots(figsize=(12, 4.2))
    ax.bar(x, values, color=colors, width=0.76, edgecolor="none")
    ax.axhline(threshold_used, color="#facc15", linestyle="--", linewidth=1.6, label=f"Review threshold: {threshold_used}")
    ax.set_xlabel("Log line")
    ax.set_ylabel("Priority score")
    ax.set_ylim(0, 105)
    if len(x) <= 28:
        ax.set_xticks(x)
    else:
        step = max(1, len(x) // 14)
        ax.set_xticks(x[::step])
    ax.grid(axis="y", alpha=0.2)
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch
    legend_items = [Patch(facecolor=color, label=severity) for severity, color in severity_colors.items() if any(item["severity"] == severity for item in chart_items)]
    legend_items.append(Line2D([0], [0], color="#facc15", linestyle="--", label=f"Threshold: {threshold_used}"))
    chart_bg = "#101c2b" if THEME == "Dark" else "#ffffff"
    chart_text = "#e7eef7" if THEME == "Dark" else "#24364b"
    fig.patch.set_facecolor(chart_bg)
    ax.set_facecolor(chart_bg)
    ax.tick_params(axis="both", colors=chart_text)
    ax.xaxis.label.set_color(chart_text)
    ax.yaxis.label.set_color(chart_text)
    for spine in ax.spines.values():
        spine.set_color("#28384d" if THEME == "Dark" else "#d8e6f5")
    ax.legend(handles=legend_items, ncol=min(4, len(legend_items)), loc="upper center", bbox_to_anchor=(0.5, 1.18), facecolor=chart_bg, labelcolor=chart_text, edgecolor="#28384d" if THEME == "Dark" else "#d8e6f5", fontsize=8)
    fig.tight_layout()
    st.pyplot(fig, width="stretch")
    plt.close(fig)

    if not anomalies:
        st.success("Nothing crossed the selected review threshold. If the system is behaving unexpectedly, check warnings and nearby log lines too.")
    else:
        st.markdown("#### Start with these lines")
        ranked = sorted(anomalies, key=lambda item: (-item["score"], item["line_number"]))
        visible_ranked = ranked[:6]
        if len(ranked) > len(visible_ranked):
            st.caption(f"Showing the top {len(visible_ranked)} findings. Open the full results table below for every analyzed line.")
        for item in visible_ranked:
            severity_class = item["severity"].lower()
            st.markdown(f'<span class="severity-badge severity-{severity_class}">{item["severity"]}</span> <span class="muted-note">{item["category"]} · line {item["line_number"]} · score {item["score"]:.0f}/100</span>', unsafe_allow_html=True)
            label = f"{item['category']} · line {item['line_number']} · priority {item['score']:.0f}/100"
            with st.expander(label, expanded=(item is visible_ranked[0])):
                left, right = st.columns([1, 2])
                left.markdown(f"**Severity:** {item['severity']}")
                left.markdown(f"**Matching lines:** {item['template_count']}")
                left.markdown(f"**Pattern score:** {item['rarity_score']:.1f}")
                left.markdown(f"**N-gram novelty:** {item['ngram_score']:.1f}/20")
                if item["security_review_boost"]:
                    left.markdown(f"**Security review score:** {item['security_review_boost']:.1f}")
                right.markdown(f"**Assessment:** {item['explanation']}")
                st.code(item["line"], language=None)
                st.markdown("**Recommended next step**")
                st.write(item["action"])

    with st.expander("See every analyzed line"):
        display_rows = [{
            "Line": item["line_number"],
            "Severity": item["severity"],
            "Score": item["score"],
            "N-gram novelty": item["ngram_score"],
            "Review": "Yes" if item["is_anomaly"] else "No",
            "Category": item["category"],
            "Log text": item["line"],
        } for item in results]
        st.dataframe(display_rows, width="stretch", hide_index=True)

    output = io.StringIO()
    fields = ["line_number", "severity", "score", "is_anomaly", "category", "explanation", "action", "template_count", "rarity_score", "ngram_score", "security_review_boost", "line"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for item in results:
        writer.writerow({key: item.get(key) for key in fields})
    st.download_button("Download results as CSV", output.getvalue().encode("utf-8-sig"), file_name="loganomaly-findings.csv", mime="text/csv")

st.divider()
st.caption("LogAnomaly is a general triage helper. It cannot know the full context from one line; confirm findings with nearby logs, metrics, and your system's runbook.")
