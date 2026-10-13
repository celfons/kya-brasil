"""Terminal-style demo animation for KYA Brasil (demo data from the README: ACME LTDA, BETA).

    python3 scripts/demo-gif.py /tmp/kya-demo     # writes /tmp/kya-demo.gif and /tmp/kya-demo_frames/
    # MP4 for social posts, from the frames (list.txt holds each frame's duration):
    #   cd /tmp/kya-demo_frames && ffmpeg -f concat -safe 0 -i list.txt -vf fps=30,format=yuv420p kya-demo.mp4
Needs Pillow and the DejaVu fonts. The README embeds docs/assets/demo.gif.
"""
import os
import sys
from PIL import Image, ImageDraw, ImageFont

W, H = 960, 540
PAD_X, TOP = 28, 64
LINE_H = 27
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
f = ImageFont.truetype(MONO, 18)
fb = ImageFont.truetype(MONO_B, 18)

BG, BAR = (13, 17, 23), (22, 27, 34)
C = {
    "fg": (201, 209, 217), "dim": (110, 118, 129), "prompt": (88, 166, 255), "ok": (63, 185, 80),
    "err": (248, 81, 73), "warn": (210, 153, 34), "str": (165, 214, 255), "head": (210, 168, 255),
}

# (kind, text, color, bold)
SCRIPT = [
    ("print", "# ACME's agent places an order with BETA, signing the request with its key", "dim", False),
    ("type", '$ agent.fetch("https://beta.com.br/orders", { amount: 4200, currency: "BRL" })', "fg", False),
    ("print", "  → KYA-Credential: 6d0b…   KYA-Signature: 0x9f3a…", "dim", False),
    ("pause", 8),
    ("print", "[beta.com.br] createKyaAuth() verifying who is talking…", "head", False),
    ("check", "✓ signature matches the agent key 0x7099…", "ok", False),
    ("check", "✓ credential active · issuer key 35bb864a2e87c8fd", "ok", False),
    ("check", "✓ e-CNPJ not revoked (ICP-Brasil CRL checked)", "ok", False),
    ("check", "✓ ACME LTDA · CNPJ 11.222.333/0001-81 · ATIVA", "ok", False),
    ("check", "✓ mandate: order ≤ 5,000 BRL · 4,200 of 20,000 BRL today", "ok", False),
    ("print", "  allowed: true   verdict signed (Ed25519), verifiable offline", "ok", True),
    ("pause", 18),
    ("blank",),
    ("type", '$ agent.fetch("https://beta.com.br/orders", { amount: 50000, currency: "BRL" })', "fg", False),
    ("check", "✓ signature, credential, e-CNPJ, company: all fine", "ok", False),
    ("check", "✗ mandate: 50,000 BRL exceeds max_per_operation 5,000 BRL", "err", False),
    ("print", "  allowed: false  → 403 outside the mandate", "err", True),
    ("pause", 24),
    ("end",),
]

FPS_MS = 70  # base frame duration


def chrome(d):
    d.rectangle([0, 0, W, 40], fill=BAR)
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([18 + i * 22, 14, 30 + i * 22, 26], fill=col)
    d.text((W // 2, 20), "KYA Brasil · who speaks for whom", font=ImageFont.truetype(SANS, 15), fill=C["dim"], anchor="mm")
    d.text((W - 16, 20), "demo data", font=ImageFont.truetype(SANS, 13), fill=C["warn"], anchor="rm")


def render(lines, cursor=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    chrome(d)
    y = TOP
    for text, color, bold in lines:
        if text.startswith("$ "):
            d.text((PAD_X, y), "$", font=fb, fill=C["prompt"])
            d.text((PAD_X + 22, y), text[2:], font=f, fill=C[color])
        else:
            d.text((PAD_X, y), text, font=fb if bold else f, fill=C[color])
        y += LINE_H
    if cursor is not None:
        cx = PAD_X + (22 + f.getlength(cursor[0][2:]) if cursor[0].startswith("$ ") else f.getlength(cursor[0]))
        d.rectangle([cx + 2, cursor[1] + 3, cx + 12, cursor[1] + 22], fill=C["fg"])
    return img


def end_card():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((W // 2, 150), "KYA Brasil", font=ImageFont.truetype(SANS_B, 58), fill=(255, 255, 255), anchor="mm")
    d.text((W // 2, 215), "Know-your-agent, backed by a real company", font=ImageFont.truetype(SANS, 26), fill=C["fg"], anchor="mm")
    d.text((W // 2, 262), "e-CNPJ-signed mandates · revocation checked daily · signed verdicts", font=ImageFont.truetype(SANS, 18), fill=C["dim"], anchor="mm")
    d.text((W // 2, 330), "Open source · MIT · self-hostable · MCP + HTTP · x402", font=ImageFont.truetype(SANS_B, 20), fill=C["ok"], anchor="mm")
    d.text((W // 2, 400), "github.com/celfons/kya-brasil", font=ImageFont.truetype(MONO_B, 24), fill=C["prompt"], anchor="mm")
    d.text((W // 2, 444), "npm i @kya-brasil/agent-tools", font=ImageFont.truetype(MONO, 20), fill=C["str"], anchor="mm")
    return img


frames, durations = [], []


def push(img, ms):
    frames.append(img)
    durations.append(ms)


lines = []
for step in SCRIPT:
    kind = step[0]
    if kind == "print":
        lines.append((step[1], step[2], step[3]))
        push(render(lines), FPS_MS * 6)
    elif kind == "check":
        lines.append(("  " + step[1], step[2], step[3]))
        push(render(lines), FPS_MS * 7)
    elif kind == "type":
        text = step[1]
        y = TOP + len(lines) * LINE_H
        for n in range(2, len(text) + 1, 3):
            push(render(lines + [(text[:n], step[2], step[3])], (text[:n], y)), 45)
        lines.append((text, step[2], step[3]))
        push(render(lines), FPS_MS * 4)
    elif kind == "pause":
        durations[-1] += FPS_MS * step[1]
    elif kind == "blank":
        lines = []
        push(render(lines), FPS_MS * 3)
    elif kind == "end":
        push(end_card(), 4500)

out = sys.argv[1]
os.makedirs(f"{out}_frames", exist_ok=True)
pal = [fr.convert("P", palette=Image.Palette.ADAPTIVE, colors=64) for fr in frames]
pal[0].save(out + ".gif", save_all=True, append_images=pal[1:], duration=durations, loop=0, optimize=True, disposal=1)
for i, fr in enumerate(frames):
    fr.save(f"{out}_frames/{i:04d}.png")
with open(f"{out}_frames/list.txt", "w") as fh:
    for i, ms in enumerate(durations):
        fh.write(f"file '{i:04d}.png'\nduration {ms / 1000}\n")
    fh.write(f"file '{len(durations) - 1:04d}.png'\n")
print(len(frames), "frames,", sum(durations) / 1000, "s")
