# demo.tape - records the Attestral "10-second demo" GIF.
#
# What it shows: a user runs `attestral scan` on a realistic-but-insecure
# MCP/agent project and instantly sees a wall of CRITICAL/HIGH agentic findings.
#
# Render (run from the REPO ROOT so the paths resolve):
#     vhs examples/vulnerable-agent/demo.tape
# ...which writes examples/vulnerable-agent/demo.gif
#
# vhs is a single Go binary: https://github.com/charmbracelet/vhs
#     brew install vhs           # macOS (pulls ttyd + ffmpeg)
#     go install github.com/charmbracelet/vhs@latest

Output examples/vulnerable-agent/demo.gif

Require attestral

Set Shell "bash"
Set FontSize 17
Set Width 1260
Set Height 1000
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms

# Start on a clean prompt.
Hide
Type "clear" Enter
Show
Sleep 600ms

# Type the one command a user would actually run.
Type "attestral scan examples/vulnerable-agent"
Sleep 900ms
Enter

# Let the findings land and hold on them so the loop reads cleanly.
Sleep 4s
