"""Quick smoke test: runs a few hand-picked inputs through the test driver."""
from test_driver import run

tests = [
    ("ipv4", "1.2.3.4"),                        # valid
    ("ipv4", "255.255.255.255"),                 # valid boundary
    ("ipv4", "192.123249324.3242334.2343"),      # invalidity (from README)
    ("ipv4", "999.999.999.999"),                 # out-of-range octets
    ("ipv4", "abc.def.ghi.jkl"),                # alpha chars
]

for target, ipstr in tests:
    r = run(target, ipstr)
    exc = r.exception_msg[:70] if r.exception_msg else "(none)"
    print(f"  [{r.bug_type:12s}] {repr(ipstr):42s} | {exc}")
