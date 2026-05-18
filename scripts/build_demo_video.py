"""Build the gemini-splunk-security-agent demo video end-to-end."""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


W, H = 1920, 1080
FG = "#0f172a"
FG_MUTED = "#475569"
ACCENT = "#7c2d12"      # SIFT forensic red-brown
ACCENT_2 = "#16a34a"    # verdict green
ACCENT_3 = "#dc2626"    # alarm red
BG = "#ffffff"
PANEL = "#f8fafc"
CODE_BG = "#0b1220"
CODE_FG = "#e2e8f0"
CODE_DIM = "#94a3b8"
CODE_GREEN = "#86efac"
CODE_RED = "#fca5a5"
CODE_YELLOW = "#fde68a"

SF = "/System/Library/Fonts/SFNS.ttf"
SFI = "/System/Library/Fonts/SFNSItalic.ttf"
MONO = "/System/Library/Fonts/SFNSMono.ttf"
if not Path(MONO).exists():
    MONO = "/System/Library/Fonts/Menlo.ttc"


def font(size, mono=False, italic=False):
    path = MONO if mono else (SFI if italic else SF)
    return ImageFont.truetype(path, size)


@dataclass
class Slide:
    name: str
    narration: str
    draw: callable


def base(img, d, title=None, eyebrow=None):
    d.rectangle([(0, H - 56), (W, H)], fill=PANEL)
    d.text((48, H - 44), "gemini-splunk-security-agent", font=font(22), fill=FG)
    d.text((W - 700, H - 44),
           "github.com/MukundaKatta/gemini-splunk-security-agent",
           font=font(22), fill=FG_MUTED)
    if eyebrow:
        d.text((96, 80), eyebrow.upper(), font=font(26), fill=ACCENT)
    if title:
        d.text((96, 130), title, font=font(72), fill=FG)
        d.rectangle([(96, 230), (220, 236)], fill=ACCENT)


def draw_title(img, d):
    d.rectangle([(0, 0), (W, H)], fill=BG)
    d.rectangle([(0, H - 56), (W, H)], fill=PANEL)
    d.text((48, H - 44),
           "github.com/MukundaKatta/gemini-splunk-security-agent",
           font=font(22), fill=FG_MUTED)
    d.text((W - 270, H - 44), "Apache 2.0", font=font(22), fill=FG_MUTED)
    d.text((96, 270), "gemini-splunk-security-agent", font=font(96), fill=FG)
    d.rectangle([(96, 400), (340, 410)], fill=ACCENT)
    d.text((96, 450),
           "Forensic incident response that",
           font=font(48), fill=FG_MUTED)
    d.text((96, 510),
           "self-corrects when the bait is bait.",
           font=font(48), fill=FG_MUTED)
    d.text((96, 720), "Splunk Agentic Ops (Security track) hackathon,", font=font(32), fill=FG)
    d.text((96, 765),
           "Splunk Security + Splunk Security track.",
           font=font(32), fill=FG)


def draw_problem(img, d):
    base(img, d, title="The trap", eyebrow="Why this agent")
    lines = [
        ("update_helper.exe fires a malware alert overnight.", FG),
        ("", FG),
        ("Surface evidence screams attack:", FG_MUTED),
        ("  runs from C:\\Windows\\Temp", FG),
        ("  triggered by a scheduled task", FG),
        ("  obfuscated string table", FG),
        ("  base64 PowerShell wrapper", FG),
        ("", FG),
        ("A weaker agent stops here and pages the on-call.",
         FG_MUTED),
        ("This one keeps walking.", ACCENT),
    ]
    y = 290
    for line, col in lines:
        d.text((96, y), line, font=font(36), fill=col)
        y += 60


def draw_architecture(img, d):
    base(img, d, title="How it works", eyebrow="Architecture")
    box_w = 380
    boxes = [
        ("User asks",     "is this an incident?",          ACCENT),
        ("ADK LlmAgent",  "Gemini 2.5 on Vertex AI",       FG),
        ("Splunk Security", "7 forensic tools via MCP",      ACCENT_2),
    ]
    x = (W - 3 * box_w - 100) // 2
    for label, sub, color in boxes:
        d.rounded_rectangle(
            [(x, 360), (x + box_w, 490)],
            radius=14, outline=color, width=4, fill=BG,
        )
        d.text((x + 24, 380), label, font=font(32), fill=FG)
        d.text((x + 24, 430), sub, font=font(22), fill=FG_MUTED)
        x += box_w + 50
    a1 = ((W - 3 * box_w - 100) // 2) + box_w + 6
    a2 = a1 + box_w + 50
    d.text((a1, 410), "→", font=font(60), fill=FG_MUTED)
    d.text((a2, 410), "→", font=font(60), fill=FG_MUTED)
    d.text((96, 620),
           "Tool surface mirrors the Splunk Security MCP server.",
           font=font(30), fill=FG)
    d.text((96, 670),
           "Stub for demos, real cluster via SPLUNK_TOKEN.",
           font=font(30), fill=FG)
    d.text((96, 780),
           "Seven tools: list_notable_events, get_notable_event, threat_intel_lookup,",
           font=font(28, italic=True), fill=FG_MUTED)
    d.text((96, 820),
           "asset_lookup, get_soar_playbook_state,"
           ".",
           font=font(28, italic=True), fill=FG_MUTED)


def draw_initial(img, d):
    base(img, d, title="Initial hypothesis", eyebrow="Step 1-2")
    d.rounded_rectangle(
        [(96, 290), (W - 96, H - 140)], radius=18, fill=CODE_BG,
    )
    lines = [
        ("$ python -m gemini_splunk_security_agent.cli --case INC-2026-0518-A-001",
         CODE_DIM),
        ("", CODE_FG),
        ("> list_notable_events", CODE_YELLOW),
        ("  art-001  C:\\Windows\\Temp\\update_helper.exe", CODE_FG),
        ("  art-002  PowerShell evtx (base64, iex)",        CODE_FG),
        ("  art-003  \\IT\\NightlyMaintenance (SYSTEM)",    CODE_FG),
        ("", CODE_FG),
        ("> get_notable_event update_helper.exe",  CODE_YELLOW),
        ("  indicators: run_from_temp,",        CODE_RED),
        ("              scheduled_task_trigger,", CODE_RED),
        ("              obfuscated_string_table", CODE_RED),
        ("", CODE_FG),
        ("INITIAL HYPOTHESIS:", CODE_DIM),
        ("  update_helper.exe is malware.",     CODE_RED),
    ]
    y = 320
    for line, col in lines:
        d.text((130, y), line, font=font(28, mono=True), fill=col)
        y += 46


def draw_evidence(img, d):
    base(img, d, title="Then it keeps walking", eyebrow="Step 3-7")
    d.rounded_rectangle(
        [(96, 290), (W - 96, H - 140)], radius=18, fill=CODE_BG,
    )
    lines = [
        ("> threat_intel_lookup update_helper.exe", CODE_YELLOW),
        ("  signed_by:  Microsoft Corporation",         CODE_GREEN),
        ("  signature_valid:  true", CODE_GREEN),
        ("", CODE_FG),
        ("> threat_intel_lookup d3b07384...39201", CODE_YELLOW),
        ("  feeds: mandiant, crowdstrike, abusedb, internal-ti", CODE_DIM),
        ("  verdict: clean", CODE_GREEN),
        ("", CODE_FG),
        ("> asset_lookup art-001", CODE_YELLOW),
        ("  user_context:  DOMAIN\\svc_endpoint_admin", CODE_GREEN),
        ("  (sanctioned service account)", CODE_DIM),
        ("", CODE_FG),
        ("> asset_lookup approved_change_window", CODE_YELLOW),
        ("  approved:  true", CODE_GREEN),
        ("  change_id: CR-2026-MAY-0517", CODE_GREEN),
    ]
    y = 320
    for line, col in lines:
        d.text((130, y), line, font=font(26, mono=True), fill=col)
        y += 44


def draw_correction(img, d):
    base(img, d, title="The self-correction", eyebrow="In the open")
    d.rounded_rectangle(
        [(96, 290), (W - 96, 720)], radius=18, fill=CODE_BG,
    )
    lines = [
        ("SELF-CORRECTION:", CODE_DIM),
        ("  surface said malware.", CODE_RED),
        ("  signature, IOC feeds, parent process,", CODE_FG),
        ("  and approved change window all disagree.", CODE_FG),
        ("  verdict flipped.", CODE_GREEN),
        ("", CODE_FG),
        ("FINAL VERDICT:", CODE_DIM),
        ("  FALSE POSITIVE - sanctioned admin activity.", CODE_GREEN),
        ("  Routine endpoint health-check rollout under", CODE_FG),
        ("  CR-2026-MAY-0517.", CODE_FG),
    ]
    y = 320
    for line, col in lines:
        d.text((130, y), line, font=font(30, mono=True), fill=col)
        y += 42
    d.text((96, 770),
           "Forensic verdict comes with its own contradicting evidence.",
           font=font(28, italic=True), fill=FG_MUTED)
    d.text((96, 815),
           "That is the whole point of Splunk Agentic Ops (Security track).",
           font=font(28, italic=True), fill=FG_MUTED)


def draw_code(img, d):
    base(img, d, title="The implementation", eyebrow="Six lines of ADK")
    code = (
        "from google.adk.agents import LlmAgent\n"
        "from google.adk.tools.mcp_tool import McpToolset\n"
        "from gemini_splunk_security_agent.agent import _protocol_sift_toolset\n"
        "\n"
        "agent = LlmAgent(\n"
        "    model='gemini-2.5-flash',\n"
        "    name='gemini_splunk_security_agent',\n"
        "    instruction=SYSTEM_PROMPT,  # forces self-correction\n"
        "    tools=[_protocol_sift_toolset(stub=True)],\n"
        ")"
    )
    d.rounded_rectangle(
        [(96, 320), (W - 96, H - 130)], radius=18, fill=CODE_BG,
    )
    yy = 360
    for line in code.split("\n"):
        d.text((130, yy), line, font=font(30, mono=True), fill=CODE_FG)
        yy += 46


def draw_close(img, d):
    d.rectangle([(0, 0), (W, H)], fill=BG)
    d.text((96, 180), "gemini-splunk-security-agent", font=font(70), fill=FG)
    d.rectangle([(96, 270), (340, 280)], fill=ACCENT)
    d.text((96, 320),
           "github.com/MukundaKatta/gemini-splunk-security-agent",
           font=font(32, mono=True), fill=ACCENT)
    d.text((96, 400),
           "gemini-splunk-security-agent-1029931682737.us-central1.run.app",
           font=font(30, mono=True), fill=ACCENT_2)
    d.text((96, 530),
           "Google Cloud Agent Builder (ADK)",
           font=font(32), fill=FG_MUTED)
    d.text((96, 580),
           "+ Gemini 2.5 on Vertex AI",
           font=font(32), fill=FG_MUTED)
    d.text((96, 630),
           "+ Splunk Security MCP server (stub + real-cluster ready)",
           font=font(32), fill=FG_MUTED)
    d.text((96, 740),
           "Tier-2 analyst that forms a hypothesis, walks the evidence,",
           font=font(26, italic=True), fill=FG_MUTED)
    d.text((96, 780),
           "and revises the verdict in the open. Splunk Agentic Ops (Security track).",
           font=font(26, italic=True), fill=FG_MUTED)
    d.text((96, 870),
           "Apache 2.0. Mukunda Katta, independent.",
           font=font(28, italic=True), fill=FG_MUTED)


SLIDES = [
    Slide(
        "01_title",
        "Protocol sift agent. Forensic incident response that "
        "self corrects when the bait is bait. Built for the find evil "
        "hackathon on the SANS sift and protocol sift track.",
        draw_title,
    ),
    Slide(
        "02_problem",
        "Overnight, update helper dot e x e fires a malware alert. "
        "Surface evidence screams attack. It runs from C colon backslash "
        "Windows backslash Temp. It is triggered by a scheduled task. "
        "Its strings are obfuscated. A base64 power shell wrapper is in "
        "the event log. A weaker agent stops here and pages the on call. "
        "This one keeps walking.",
        draw_problem,
    ),
    Slide(
        "03_architecture",
        "Three boxes. A user question is, is this an incident. It goes "
        "into an A D K L L M agent powered by Gemini two point five on "
        "Vertex A I. The agent uses M C P toolset to call the Protocol "
        "sift M C P server with seven tools. List artifacts. Examine "
        "binary. Compute hash. Check i o c. Get process tree. Query "
        "event log. List persistence mechanisms. Stub for demos, real "
        "cluster one A P I token away.",
        draw_architecture,
    ),
    Slide(
        "04_initial",
        "Step one and two. The agent calls list artifacts and sees the "
        "binary in C colon Windows Temp. It calls examine binary and "
        "records the suspicious indicators. Run from temp. Scheduled "
        "task trigger. Obfuscated string table. Based on these surface "
        "indicators alone, it states its initial hypothesis. Update "
        "helper dot e x e is malware. This is exactly where a weaker "
        "agent would stop.",
        draw_initial,
    ),
    Slide(
        "05_evidence",
        "Steps three through seven. Compute hash returns signed by "
        "Microsoft Corporation, signature valid true. Check i o c "
        "against four threat intel feeds, mandiant, crowdstrike, "
        "abusedb, internal t i. Verdict clean, zero matches. Get "
        "process tree returns user context domain backslash s v c "
        "endpoint admin, a sanctioned service account. Query event "
        "log approved change window returns approved true, change i d "
        "C R 2026 May 0517. The deeper evidence disagrees with the "
        "surface.",
        draw_evidence,
    ),
    Slide(
        "06_correction",
        "Self correction. Surface said malware. Signature, i o c feeds, "
        "parent process, and approved change window all disagree. "
        "Verdict flipped. Final verdict, false positive, sanctioned "
        "admin activity, a routine endpoint health check rollout under "
        "change request C R 2026 May 0517. The forensic verdict comes "
        "with its own contradicting evidence. That is the whole point "
        "of find evil.",
        draw_correction,
    ),
    Slide(
        "07_code",
        "The agent fits in six lines of Google's A D K. One L L M "
        "agent, one M C P toolset bound to the stub or real protocol "
        "sift server, a Gemini model, and a system prompt that forces "
        "labeled initial hypothesis, self correction, and final verdict "
        "sections on every run.",
        draw_code,
    ),
    Slide(
        "08_close",
        "Protocol sift agent. Apache two point zero. Tier 2 analyst "
        "that forms a hypothesis, walks the evidence, and revises the "
        "verdict in the open. Find evil. Thank you.",
        draw_close,
    ),
]


def render_slides(outdir):
    paths = []
    for sl in SLIDES:
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        sl.draw(img, d)
        p = outdir / f"{sl.name}.png"
        img.save(p, "PNG", optimize=True)
        paths.append(p)
        print(f"  rendered {p.name}")
    return paths


def render_audio(outdir):
    paths = []
    for sl in SLIDES:
        wav = outdir / f"{sl.name}.aiff"
        m4a = outdir / f"{sl.name}.m4a"
        subprocess.run(
            ["say", "-v", "Samantha", "-r", "175", "-o", str(wav),
             sl.narration],
            check=True,
        )
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-i", str(wav),
             "-c:a", "aac", "-b:a", "128k", str(m4a)],
            check=True,
        )
        wav.unlink(missing_ok=True)
        paths.append(m4a)
        print(f"  spoke   {m4a.name}")
    return paths


def render_segments(outdir, slide_pngs, audio_m4as):
    segs = []
    for sl, png, m4a in zip(SLIDES, slide_pngs, audio_m4as):
        out = outdir / f"seg_{sl.name}.mp4"
        dur = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", str(m4a)],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        seg_dur = float(dur) + 0.4
        subprocess.run([
            "ffmpeg", "-y", "-loglevel", "error",
            "-loop", "1", "-i", str(png),
            "-i", str(m4a),
            "-af", "apad=pad_dur=0.4",
            "-c:v", "libx264", "-tune", "stillimage", "-pix_fmt", "yuv420p",
            "-r", "30", "-t", f"{seg_dur:.2f}",
            "-c:a", "aac", "-b:a", "128k",
            "-shortest", str(out),
        ], check=True)
        segs.append(out)
        print(f"  segment {out.name}  ({seg_dur:.2f}s)")
    return segs


def concat(outdir, segs):
    list_file = outdir / "concat.txt"
    list_file.write_text(
        "\n".join(f"file '{p.resolve()}'" for p in segs) + "\n"
    )
    out = outdir / "demo.mp4"
    subprocess.run([
        "ffmpeg", "-y", "-loglevel", "error",
        "-f", "concat", "-safe", "0", "-i", str(list_file),
        "-c", "copy", str(out),
    ], check=True)
    return out


def main():
    outdir = (
        Path(sys.argv[1]) if len(sys.argv) > 1
        else Path.home() / "gemini-splunk-security-agent" / ".video-build"
    )
    outdir.mkdir(parents=True, exist_ok=True)
    for needed in ("ffmpeg", "ffprobe", "say"):
        if shutil.which(needed) is None:
            sys.exit(f"missing tool: {needed}")
    print("[1/4] slides...")
    slides = render_slides(outdir)
    print("[2/4] audio...")
    audios = render_audio(outdir)
    print("[3/4] segments...")
    segs = render_segments(outdir, slides, audios)
    print("[4/4] concat...")
    final = concat(outdir, segs)
    size = final.stat().st_size / (1024 * 1024)
    dur = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", str(final)],
        capture_output=True, text=True,
    ).stdout.strip()
    print(f"\nDONE: {final}  ({size:.1f} MB, {float(dur):.1f}s)")


if __name__ == "__main__":
    main()
