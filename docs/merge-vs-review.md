# Path forward — review vs. land-and-test

> **⚠️ HISTORICAL.** This doc captures the trade-off analysis from
> when there were two open PRs (#173 + #174). **PR #174 was closed** as
> a strict subset of PR #173, so the "choose one of (a)(b)(c)" decision
> below is no longer live. The active mode is **single unified branch +
> external eBPF consultant review on PR #173**, per the recommendation
> in this doc's Option B.
>
> Kept for historical traceability. See
> [`reviewer-guide.md`](reviewer-guide.md) for the up-to-date review
> instructions.


**Question on the table:** PR #174 and PR #173 together are ~22k LOC of
diff. Do we (a) put them through full code review before anything
lands, or (b) merge to a long-lived branch / `main` and let people
build & test the binary while review happens in parallel?

This doc lays out the options, the trade-offs, and my recommendation.

---

## What you can already do TODAY without merging anything

This is the most important fact and the one that's easy to forget:
**nothing needs to be merged for you to build and test the agent from
the branch.** From any machine with the dev container set up:

```bash
git fetch origin
git checkout feat/https-capture-ebpf       # the rolling branch (PR #173 head)
make build-ebpf                            # produces bin/postman-insights-agent
./bin/postman-insights-agent apidump --enable-https-capture …
```

So if the goal is "I want to hold the binary in my hands and exercise
it," that goal is achievable today by pulling the branch. Merging is a
separate decision about **shipping** and **review scope**.

The one thing missing locally as of writing this doc: the 2 commits
on top of `origin/feat/https-capture-ebpf` (the Phase 5 plan doc + the
Phase 5a implementation). Once pushed, the remote branch builds the
agent with Phase 5a included.

---

## The three real options

### Option A — Full review of both PRs, then merge

Engineers review PR #174 first (≈90 min – 3 h with the
[reviewer's guide](reviewer-guide.md)), merge it, GitHub auto-narrows
PR #173 to ~7.7k LOC of net-new code, engineers review that
(≈2 h – 6 h), merge it.

**Pros**
* Most rigorous. Both PRs hit `main` only after human approval.
* Future contributors can `git blame` and find clean review history.

**Cons**
* Reviewer time cost is real — 4-9 person-hours minimum, spread across
  weeks if reviewers are part-time. Calendar time, not work hours.
* You can't usefully iterate on Phase 5b until the underlying foundation
  is either merged or reviewers explicitly say "okay to layer more on."
* Big PRs get less thorough review than small ones (well-documented
  empirical pattern). 22k LOC + 8k LOC of Phases-1-through-5a, no
  matter how well organised, is going to get rubber-stamped by some
  reviewers and bike-shedded by others.

### Option B — Merge PR #174 to `main`, keep #173 as a long-lived test branch (RECOMMENDED)

PR #174 is the polished slice. It has:
* 6/6 exit criteria green, evidenced in `phase-1-results.md` +
  `phase-2-results.md`.
* A real kind-cluster e2e demo.
* A clear `--enable-https-capture` opt-in flag (off by default — zero
  risk to existing users).
* Reasonable scope (8k LOC across 70 files; nothing in there is "spike-quality").

Once #174 lands on `main`:
* `feat/https-capture-ebpf` (PR #173 head) becomes the place we
  continue iterating Phase 3 / 4 / 5b / 5c. You build & test from it.
* Engineers who want to review #173 see the narrowed +7.7k diff, which
  is much more approachable. They can review at their own pace; you
  keep shipping.
* Phase 5a (which is in #173 today) stays on the branch and ships when
  the rest of #173 ships — natural cadence.

**Pros**
* Half of the program is on `main` with a clear paper trail.
* Removes the "everything is blocked on review" feeling.
* Future Phase 5b/5c PRs target the `feat/https-capture-ebpf` branch
  while it's alive, OR target `main` once we decide #173 is ready to
  merge.
* You get a "hold the binary, kick the tires" workflow on the rolling
  branch without compromising what's on `main`.

**Cons**
* `main` now carries a feature that's behind an off-by-default flag.
  Standard pattern (we already do this with telemetry, dogfood, etc.),
  but worth flagging.
* PR #173 stays "open and growing" until someone decides to either
  review-and-merge or split it further. Risk of it becoming a
  permanent-branch zombie if neglected.

### Option C — Merge everything to a long-lived branch (NOT `main`), skip review entirely

We don't open PRs to `main` at all right now. We push every commit to
`feat/https-capture-ebpf`, treat it as a "feature integration branch,"
build & test from it indefinitely. Review-to-`main` happens later, in
some yet-undefined shape.

**Pros**
* Zero review-overhead while we're still iterating.
* You can ship dogfood builds off the branch at will.

**Cons**
* Defers, rather than answers, the review question. Eventually the
  branch has to merge to `main` and the review backlog will be even
  larger then.
* If the branch survives long enough to drift from `main`, rebases
  start to hurt.
* No `git blame` story for production users when the branch eventually
  lands — they'll see one giant "feat: HTTPS capture" commit instead
  of phase-by-phase commits.

---

## My recommendation

**Option B.** Specifically:

1. **Push the 2 local commits** to `origin/feat/https-capture-ebpf` so
   the remote branch matches local. After that, you can pull and build
   Phase 5a anywhere.
2. **Cherry-pick `12b0c55`** (the non-Linux `KubeNamespaceResolver`
   stub) from PR #174's branch back onto PR #173's branch so they're
   in sync.
3. **Ask one reviewer to look at PR #174 specifically.** Hand them
   `docs/reviewer-guide.md` and `phase-1-results.md` +
   `phase-2-results.md`. Expect 2-3 hours of their time.
4. **Merge PR #174 to `main` once approved.** GitHub will auto-narrow
   PR #173 to the Phase 3+4+5a delta.
5. **Keep PR #173 open and growing** as the rolling branch through
   Phase 5b. Re-evaluate when 5b lands — at that point the branch will
   include a whole new Java agent and webhook, and you may want to
   split it into "Phase 3+4 to main" + "Phase 5 to main" PRs.
6. **Build dogfood / test agents off `feat/https-capture-ebpf`** in the
   meantime. That branch is the integration tip.

Why this and not (A) or (C):

* **vs. A:** the marginal value of formally reviewing every commit of
  Phase 3 today (when Phase 5b is going to layer on top of it in a
  week) is low. Better to merge the parts that are stable and let the
  parts still in motion stay on a branch.
* **vs. C:** completely skipping review means no `main`-visible
  paper trail for a multi-thousand-LOC change. Even the polished slice
  (#174) deserves one pair of fresh eyes before it ships.

---

## What's NOT in this trade-off

A few things might come up that this doc deliberately doesn't address —
calling them out so the conversation stays on track:

1. **"Should we just close the PRs and rewrite history?"** No — the
   commit history is meaningful (per-phase, per-task, with co-author
   trailers). Squash-merge on the GitHub UI when the time comes if
   `main` needs a single landing commit, but don't rewrite the branch.
2. **"Should Phase 5a be its own PR?"** Maybe later. Right now it's
   ~1200 LOC and well-isolated, so it's fine inside #173. Once Phase 5b
   lands (which adds a full Gradle project + JNI shim + a Java agent),
   splitting becomes worthwhile.
3. **"Can we release a public build off this?"** Not until at least
   Phase 4 is fully closed (3 of the 8 privacy gaps still open per
   `phase-4-results.md`). Internal / trial dogfood is fine; GA is not.

---

## If you choose Option B and just want the steps

```bash
# 1. Push local work to the remote branch.
git push origin feat/https-capture-ebpf

# 2. Sync the libssl branch's missing commit back into the rolling branch.
git fetch origin
git cherry-pick 12b0c55                       # the non-Linux discovery stub
git push origin feat/https-capture-ebpf

# 3. Ask a reviewer to look at PR #174 specifically. Hand them
#    docs/reviewer-guide.md and the phase-1/phase-2 results docs.

# 4. After approval, squash-merge PR #174 to main on the GitHub UI.
#    PR #173's diff will narrow automatically.

# 5. Anyone who wants to test the agent now:
git fetch origin
git checkout feat/https-capture-ebpf
make build-ebpf
sudo ./bin/postman-insights-agent apidump --enable-https-capture …
```

That's it. Reviewing #173 can happen at whatever cadence works; the
work doesn't stall.
