"""Generate sanitized lab sample logs (no real user data)."""
import random

random.seed(42)
AUTH = "sample_data/auth.log"
WEB = "sample_data/access.log"

with open(AUTH, "w") as f:
    f.write("Sep  5 09:00:01 lab sshd[101]: Accepted password for alice from 10.0.0.5 port 51234 ssh2\n")
    # brute force from TEST-NET-3 attacker
    for i in range(8):
        user = random.choice(["root", "admin", "alice"])
        f.write(f"Sep  5 09:01:{i:02d} lab sshd[{200+i}]: Failed password for {user} from 203.0.113.45 port 4000{i} ssh2\n")
    f.write("Sep  5 09:02:30 lab sshd[209]: Accepted password for root from 203.0.113.45 port 40099 ssh2\n")
    # low-noise fails (should NOT alert)
    for i in range(2):
        f.write(f"Sep  5 09:03:{i:02d} lab sshd[{300+i}]: Failed password for bob from 10.0.0.8 port 5000{i} ssh2\n")

with open(WEB, "w") as f:
    f.write('10.0.0.5 - - [05/Sep/2026:09:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n')
    # scanner: 20 unique paths, many 404
    for i in range(20):
        f.write(f'198.51.100.23 - - [05/Sep/2026:09:05:{i:02d} +0000] "GET /admin{i} HTTP/1.1" 404 0 "-" "nikto"\n')
    # exploit probes
    f.write("198.51.100.23 - - [05/Sep/2026:09:06:00 +0000] \"GET /search?q=' UNION SELECT 1-- HTTP/1.1\" 500 0 \"-\" \"curl\"\n")
    f.write("198.51.100.23 - - [05/Sep/2026:09:06:01 +0000] \"GET /../../etc/passwd HTTP/1.1\" 400 0 \"-\" \"curl\"\n")
    f.write('10.0.0.5 - - [05/Sep/2026:09:07:00 +0000] "GET /about HTTP/1.1" 200 500 "-" "Mozilla/5.0"\n')

print(f"wrote {AUTH}, {WEB}")
