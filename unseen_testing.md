python main.py bootstrap xml --refresh-bootstrap --bootstrap-examples-limit 12

# Unseen Testing Guide: XML

This note is for the "new unseen format" workflow where you want an LLM to help
you onboard XML parsing as a fresh benchmark target for this repository.

XML is a stronger benchmark-style choice than URL because it is a common parser
target in fuzzing research and is closer to established evaluation targets such
as `libxml2`.

The goal is not to ask the LLM for a whole fuzzer from scratch. The better
workflow is to give it the repository context and ask for the smallest set of
artifacts needed to plug XML into the existing pipeline:

- a format config
- a seed corpus
- an oracle strategy
- optional semantic-mutation hints
- a minimal target harness if needed

## Why Use An LLM For Unseen Targets

The rationale for using an LLM on unseen targets is to reduce the amount of
target-specific manual work needed at the exact point where the repository is
trying to prove transferability.

- An unseen target starts with little or no hand-written onboarding material,
  so the LLM is useful for producing a first-pass config, seed ideas, token
  hints, oracle sketch, and integration notes from a compact description.
- This fits the repository's evaluation goal better than hand-coding every new
  target, because it tests whether the existing pipeline can be extended with
  lightweight guidance instead of bespoke engineering.
- The LLM is most valuable as an offline bootstrap assistant, not as the hot
  mutation loop. It helps initialize structure and target knowledge before the
  normal seed, mutation, coverage, and scheduler machinery takes over.
- For unseen formats, the hardest early problem is often "what are reasonable
  valid and invalid examples?" The LLM helps answer that quickly so experiments
  can start from a useful corpus instead of random bytes.
- Using the LLM in this limited role also keeps the benchmark honest: the core
  fuzzer still has to do the real discovery work after onboarding.

In short, the LLM is used for unseen targets because it is a fast way to
bootstrap minimal target knowledge while still preserving the repository's main
claim that most of the fuzzing work should be handled by the shared engine.

## What To Ask The LLM To Generate

Ask for these outputs explicitly:

1. `config/xml_format.json`
2. `corpus/xml_seeds.txt` or `corpus/xml_seeds/`
3. a short oracle plan for classifying well-formed vs malformed XML
4. target integration notes for `main.py`, `fuzzer/executor.py`, and
   `fuzzer/oracle.py`
5. optional XML-specific semantic mutation ideas if the generic string
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

I want to add XML as a new unseen format benchmark.

Please generate:
1. A proposed config/xml_format.json
2. A starter corpus/xml_seeds.txt with diverse well-formed XML examples
3. A concise oracle strategy for deciding well-formed vs malformed XML
4. Any minimal code changes needed to register the target in this repo
5. Optional XML-specific semantic mutation operations

Constraints:
- Keep the design aligned with the current repository rather than inventing a new framework.
- Prefer stdlib-based validation where possible for the first version.
- Treat XML as a text input format.
- Favor small, testable changes.
- Return the answer as concrete file contents plus short integration notes.
```

That prompt usually works better than asking "add XML fuzzing" with no context.

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

## Inputs You Need For Actual XML Testing

For the benchmark itself, gather these concrete inputs.

### 1. Well-formed XML seeds

Start with a small but diverse set of valid examples:

```xml
<root/>
<root></root>
<root><child/></root>
<root><child>text</child></root>
<root attr="value"/>
<root a="1" b="two"/>
<root><a/><b/><c/></root>
<root><item id="1">x</item><item id="2">y</item></root>
<root><!--comment--><child/></root>
<root><![CDATA[some <unsafe> text]]></root>
<?xml version="1.0"?><root/>
<ns:root xmlns:ns="urn:test"><ns:item/></ns:root>
```

These seeds help the mutators see:

- open and close tags
- empty elements
- nested structure
- attributes
- repeated sibling elements
- comments
- CDATA
- XML declaration
- namespaces

### 2. Malformed XML examples

You also want known-invalid examples for oracle checks and regression tests:

```xml
<root>
<root></child>
<root attr=value/>
<root><child></root>
<root><child/></roo>
<root><child></child>
<root><a></b></root>
<root><
<?xml version="1.0"><root/>
<ns:root><ns:item/></ns:root>
```

Use these to verify that your oracle and target do not accept malformed shapes
too easily.

### 3. Accepted subset definition

You should decide the XML subset before evaluation. A simple and practical
subset is:

- require well-formed XML only
- allow nested elements, attributes, text, comments, and CDATA
- allow XML declaration
- allow namespaces
- do not require DTD, schema validation, XPath, or XInclude support
- avoid external entity resolution in the first benchmark version

Defining the accepted subset matters because "valid XML" can mean either
well-formed XML or schema/DTD-valid XML. For this repository, well-formedness
is the cleaner first benchmark.

### 4. Oracle implementation choice

For this repository, the easiest testing input to give the LLM is:

- "use a Python stdlib-based oracle where possible"
- "treat successful parsing as well-formed and parse failure as malformed"
- "disable or avoid entity-expansion and external-resource behavior in the
  first version"

In practice, the simplest oracle shape is:

- parse with `xml.etree.ElementTree.fromstring`
- accept if parsing succeeds
- reject if parsing raises `ParseError`
- optionally classify special parser exceptions separately if your target
  harness exposes them

This avoids asking the LLM to invent a full schema-aware XML validator.

## Good Semantic Mutation Hints For XML

If you want the LLM to propose XML-aware mutations, ask for operations around:

- tag rename
- close-tag mismatch
- missing close tag
- empty-element expansion and contraction
- attribute insertion, deletion, and quote damage
- namespace prefix insertion/removal
- comment insertion and truncation
- CDATA open/close damage
- sibling duplication and deletion
- subtree duplication and deletion
- declaration insertion/removal/damage

These are usually more useful than generic byte flips when the goal is parser
state exploration rather than only malformed-input discovery.

## What To Ask For If You Want A Fair Benchmark

If the real goal is evaluation rather than just implementation, ask the LLM to
produce three onboarding levels:

1. `config-only`
2. `config + seed corpus + oracle`
3. `config + seeds + oracle + small XML-specific semantic mutations`

That gives you a cleaner transfer benchmark:

- level 1 measures how far the generic pipeline goes
- level 2 measures realistic low-effort onboarding
- level 3 measures the hand-tuned upper bound

## Common Failure Modes

Watch for these when reviewing LLM output:

- it mixes up well-formedness with schema validation
- it forgets to define the accepted subset
- it turns on external entity behavior that you do not want in a first target
- it proposes a huge grammar framework when the repo mostly uses lightweight config
- it forgets seeds and only gives code
- it ignores oracle mismatch categories
- it designs a binary-file workflow even though XML is a text target

## Recommended Minimal Deliverables

For this repo, the minimum useful deliverables are:

- `config/xml_format.json`
- `corpus/xml_seeds.txt` or `corpus/xml_seeds/`
- an XML oracle helper in `fuzzer/oracle.py`
- target registration in `main.py`
- executor wiring only if the XML target is backed by a separate parser target

If you are only doing an unseen-format planning exercise, the first three are
usually enough.

## Practical Review Checklist

Before accepting the generated result, check:

- Does the config look like the existing configs?
- Are the seeds diverse and mostly well-formed?
- Is the accepted XML subset written down?
- Does the oracle reject mismatched tags, broken attributes, and truncated input?
- Does the proposal fit the current mutation pipeline?
- Does it avoid unnecessary new dependencies?

If the answer to those is yes, the LLM output is probably good enough to use as
the first XML benchmark candidate in this repository.
