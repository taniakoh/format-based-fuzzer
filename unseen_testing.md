# Unseen Testing Guide: URL

This note is for the "new unseen format" workflow where you want an LLM to help
you onboard URL parsing as a fresh benchmark target for this repository.

The goal is not to ask the LLM for a whole fuzzer from scratch. The better
workflow is to give it the repository context and ask for the smallest set of
artifacts needed to plug URL into the existing pipeline:

- a format config
- a seed corpus
- an oracle strategy
- optional semantic-mutation hints
- a minimal target harness if needed

## What To Ask The LLM To Generate

Ask for these outputs explicitly:

1. `config/url_format.json`
2. `corpus/url_seeds.txt`
3. a short oracle plan for classifying valid vs invalid URLs
4. target integration notes for `main.py`, `fuzzer/executor.py`, and
   `fuzzer/oracle.py`
5. optional URL-specific semantic mutation ideas if the generic string
   mutations are too weak

If you want code generation, ask for repository-compatible patches instead of a
generic design doc.

## Best Prompt Shape

Use a prompt that gives the LLM the repo constraints first, then the exact
outputs you want.

Example prompt:

```text
You are helping extend an existing format-aware fuzzing repository.

Current repo design:
- Targets are onboarded through config/<name>_format.json plus optional seeds.
- The pipeline is SeedGenerator -> Tier1 structure -> Tier2 semantic -> Tier3 havoc -> Executor -> Coverage -> Corpus.
- Text-oriented targets already include IPv4, IPv6, cidrize, and JSON-family formats.
- The executor supports parser binaries and Python-based targets.
- The oracle distinguishes valid inputs, expected invalid inputs, crashes, timeouts, and mismatches.

I want to add URL as a new unseen format benchmark.

Please generate:
1. A proposed config/url_format.json
2. A starter corpus/url_seeds.txt with diverse valid URL examples
3. A concise oracle strategy for deciding valid vs invalid URLs
4. Any minimal code changes needed to register the target in this repo
5. Optional URL-specific semantic mutation operations

Constraints:
- Keep the design aligned with the current repository rather than inventing a new framework.
- Prefer stdlib-based validation where possible.
- Treat URL as a text input format, not a binary format.
- Favor small, testable changes.
- Return the answer as concrete file contents plus short integration notes.
```

That prompt usually works better than asking "add URL fuzzing" with no context.

## Inputs You Should Give The LLM

For good results, provide these repository-specific inputs:

- The current target list and architecture summary from `AGENTS.md`
- One or two existing format configs:
  - `config/ipv4_format.json`
  - `config/json_format.json`
- The current execution/oracle structure:
  - `fuzzer/executor.py`
  - `fuzzer/oracle.py`
  - `main.py`
- Seed examples from nearby text formats:
  - `corpus/json_seeds.txt`
  - `corpus/cidrize_seeds.txt`

This is enough context for the model to imitate the repo's onboarding pattern
instead of inventing a mismatched solution.

## Inputs You Need For Actual URL Testing

For the benchmark itself, gather these concrete inputs:

### 1. Valid seed URLs

Start with a small but diverse set of valid examples:

```text
http://example.com
https://example.com
https://example.com/
https://example.com/path
https://example.com/path/to/file
https://example.com:443/path
https://sub.example.com/path?q=test
https://example.com/path?q=test&lang=en
https://example.com/path#fragment
ftp://ftp.example.com/resource.txt
http://127.0.0.1
http://127.0.0.1:8080/api
http://localhost
http://localhost:3000/
https://user:pass@example.com/
https://example.com/~user
https://example.com/a-b_c.d
https://example.com/%7Euser
https://[2001:db8::1]/
https://[2001:db8::1]:8443/path
```

These seeds help the mutators see:

- schemes
- hostnames
- IPv4 and IPv6 hosts
- ports
- paths
- query strings
- fragments
- percent-encoding
- optional userinfo

### 2. Invalid URL examples

You also want known-invalid examples for oracle checks and regression tests:

```text
http://
://example.com
http:///path
http://exa mple.com
http://example .com
http://example.com:abc
http://[2001:db8::1
http://2001:db8::1]
http://example.com/%
http://user@:80
http://:80
http://?
https://example.com:999999
```

Use these to verify that your oracle and target do not accept malformed shapes
too easily.

### 3. Accepted subset definition

You should decide the URL subset before evaluation. A simple and practical
subset is:

- allow schemes: `http`, `https`, `ftp`
- require a non-empty authority/host
- allow hostname, IPv4, `localhost`, or bracketed IPv6 host
- allow optional port if numeric and in range `1..65535`
- allow optional path, query, and fragment
- allow optional userinfo

Defining the accepted subset matters because full URL syntax is broad and some
libraries parse leniently.

### 4. Oracle implementation choice

For this repository, the easiest testing input to give the LLM is:

- "use a Python stdlib-based oracle where possible"
- "then tighten it with explicit checks for scheme, host presence, bracketed
  IPv6 handling, and numeric port range"

In practice, the most likely oracle shape is:

- parse with `urllib.parse.urlsplit`
- reject empty scheme
- reject missing netloc/host for the chosen subset
- validate port range
- validate IPv6 bracket form
- optionally validate hostname/IP form more strictly with small helper checks

This avoids asking the LLM to invent a full RFC-complete URL validator.

## Good Semantic Mutation Hints For URL

If you want the LLM to propose URL-aware mutations, ask for operations around:

- scheme swap: `http` <-> `https` <-> `ftp`
- host label edits
- subdomain insertion/removal
- port insertion/removal/change
- path segment duplication/deletion
- query key/value duplication, deletion, and separator damage
- fragment insertion/removal
- percent-encoding insertion/damage
- IPv4 host octet edits
- IPv6 bracket damage
- userinfo insertion/removal

These are usually more useful than generic byte flips when the goal is parser
state exploration rather than only malformed-input discovery.

## What To Ask For If You Want A Fair Benchmark

If the real goal is evaluation rather than just implementation, ask the LLM to
produce three onboarding levels:

1. `config-only`
2. `config + seed corpus + oracle`
3. `config + seeds + oracle + small URL-specific semantic mutations`

That gives you a cleaner transfer benchmark:

- level 1 measures how far the generic pipeline goes
- level 2 measures realistic low-effort onboarding
- level 3 measures the hand-tuned upper bound

## Common Failure Modes

Watch for these when reviewing LLM output:

- it treats URL validation as "any string parseable by a library is valid"
- it forgets to define the accepted subset
- it proposes browser-specific URL behavior that is too permissive
- it adds a giant custom grammar when the repo mostly uses lightweight config
- it forgets seeds and only gives code
- it ignores oracle mismatch categories
- it designs a binary-file workflow even though URL is a text target

## Recommended Minimal Deliverables

For this repo, the minimum useful deliverables are:

- `config/url_format.json`
- `corpus/url_seeds.txt`
- a URL oracle helper in `fuzzer/oracle.py`
- target registration in `main.py`
- executor wiring only if the URL target is backed by a separate parser target

If you are only doing an unseen-format planning exercise, the first three are
usually enough.

## Practical Review Checklist

Before accepting the generated result, check:

- Does the config look like the existing configs?
- Are the seeds diverse and mostly valid?
- Is the accepted URL subset written down?
- Does the oracle reject clearly malformed ports and broken IPv6 brackets?
- Does the proposal fit the current mutation pipeline?
- Does it avoid unnecessary new dependencies?

If the answer to those is yes, the LLM output is probably good enough to use as
the first URL benchmark candidate in this repository.
