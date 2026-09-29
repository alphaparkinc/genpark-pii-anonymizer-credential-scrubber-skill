from client import PIICredentialScrubber

raw = "User Bob (bob@domain.com) reported an issue from IP 192.168.1.1. Key: ghp_1234567890abcdef1234567890abcdef1234"
res = PIICredentialScrubber.scrub(raw)

print("Scrubbed Text:", res["scrubbed_text"])
print("Detected Findings:", res["findings"])
