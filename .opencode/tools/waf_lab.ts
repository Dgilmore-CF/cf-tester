import { tool, type ToolContext } from "@opencode-ai/plugin"
import { spawn } from "node:child_process"
import { constants } from "node:fs"
import { access } from "node:fs/promises"
import { isIP } from "node:net"
import path from "node:path"
import { isDeepStrictEqual } from "node:util"

const uuid = tool.schema.string().uuid()
const digest = tool.schema.string().regex(/^[a-f0-9]{64}$/)
function normalizeTarget(value: string): string | undefined {
  if (/[^\x21-\x7e]/.test(value)) return undefined
  // Parse literal syntax before URL normalization can erase dot segments or empty credentials.
  const match = /^(?:https:\/\/)?([^/:]+)(?::443)?(\/[a-zA-Z0-9/_.~-]*)?$/i.exec(value)
  if (!match?.[1]) return undefined
  const host = match[1].toLowerCase()
  const basePath = match[2] ?? "/"
  const labels = host.split(".")
  if (host.length > 253 || labels.length < 2 || isIP(host) || /^[\d.]+$/.test(host) ||
      labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
      basePath.split("/").some((segment) => segment === "." || segment === "..")) return undefined
  return `https://${host}${basePath}`
}

const target = tool.schema.string().refine((value) => normalizeTarget(value) !== undefined,
  "Use a DNS hostname or HTTPS/443 URL with a literal base path: no credentials (even empty), query, fragment, IP, wildcard, encoding, or dot segment; use punycode for IDNs")
const targets = tool.schema.array(target).min(1).max(10)
const profile = tool.schema.enum([
  "smoke", "sqli", "xss", "command", "traversal", "ssti", "ldap", "xxe",
  "ssrf", "prototype", "log4j", "scanner", "managed", "all",
])
const profiles = tool.schema.array(profile).min(1).max(14)
const smokeMethod = tool.schema.enum(["GET", "HEAD"])
const redirectPolicy = tool.schema.object({
  enabled: tool.schema.boolean(),
  max_hops: tool.schema.number().finite().int().min(0).max(3),
  destinations: tool.schema.array(target).max(10),
}).strict()
const requestCase = tool.schema.object({
  case_id: tool.schema.string().min(1),
  target,
  method: tool.schema.enum(["GET", "HEAD", "POST"]),
  url: tool.schema.string().min(1).refine((value) => {
    try {
      if (!/^https:\/\/[^/?#@\\]+(?:[/?][^#\\]*)?$/i.test(value) || /[^\x21-\x7e]/.test(value)) return false
      const url = new URL(value)
      return url.protocol === "https:" && !url.username && !url.password && !url.hash &&
        (!url.port || url.port === "443") && normalizeTarget(`https://${url.hostname}/`) !== undefined &&
        !/[\x00-\x20\x7f]/.test(value)
    } catch { return false }
  }, "Request URL must be complete HTTPS/443 without credentials or fragment"),
  headers: tool.schema.record(tool.schema.string().regex(/^[!#$%&'*+.^_`|~\w-]+$/),
    tool.schema.string().refine((value) => !/[\r\n\0]/.test(value))),
  body: tool.schema.string().nullable(),
}).passthrough()
const reviewOptions = tool.schema.object({
  offset: tool.schema.number().finite().int().min(0),
  limit: tool.schema.number().finite().int().min(1).max(5),
})
const reviewPage = tool.schema.object({
  plan_id: uuid,
  approval_digest: digest,
  ...reviewOptions.shape,
  total: tool.schema.number().finite().int().min(1).max(500),
  items: tool.schema.array(requestCase).max(5),
  more: tool.schema.boolean(),
  review_text: tool.schema.string().min(1),
}).strict()
const reportOptions = tool.schema.object({
  section: tool.schema.enum(["summary", "attempts", "rules", "plan", "inventory"]),
  offset: tool.schema.number().finite().int().min(0),
  limit: tool.schema.number().finite().int().min(1).max(50),
})
const budgets = tool.schema.object({
  max_requests: tool.schema.number().finite().int().min(1).max(500),
  rate_per_second: tool.schema.number().finite().min(0.1).max(2),
  max_runtime_seconds: tool.schema.number().finite().int().min(1).max(600),
  timeout_seconds: tool.schema.number().finite().int().min(1).max(30),
  concurrency: tool.schema.literal(1).optional(),
}).passthrough().refine((value) => value.timeout_seconds <= value.max_runtime_seconds,
  "Request timeout cannot exceed runtime budget")
const savedPlan = tool.schema.object({
  plan_id: uuid,
  approval_digest: digest,
  targets,
  profiles,
  smoke_method: smokeMethod,
  cases: tool.schema.array(requestCase).min(1).max(500),
  redirect_policy: redirectPolicy,
  redirect_requests: tool.schema.array(requestCase.extend({ source_case_id: tool.schema.string().min(1) })).max(500),
  maximum_sends: tool.schema.number().finite().int().min(1).max(500),
  follow_redirects: tool.schema.literal(false),
  concurrency: tool.schema.literal(1),
  budgets,
  catalogue_version: tool.schema.string().min(1),
  created_at: tool.schema.string().min(1),
  dns_pins: tool.schema.record(tool.schema.string(), tool.schema.array(tool.schema.string().min(1)).min(1)),
  inventory: tool.schema.unknown(),
  warnings: tool.schema.array(tool.schema.string()),
}).passthrough()

const risk = "Authorized testing only. Low-impact probes are NOT harmless on vulnerable applications. " +
  "Use an inert lab origin/route, review every request and warning, and expect possible blocks, " +
  "challenges, origin side effects, logging, and cost. HTTPS port 443 only; public DNS pins; " +
  "redirects disabled unless explicitly authorized and manually matched to reviewed GET/HEAD routes; " +
  "POST never follows; concurrency 1. Never auto-approve or choose always."
const sessionPlans = new Map<string, {
  digest: string; plan: unknown; reviews: Set<number>; reviewTexts: Set<string>
}>()

type CliResult = { stdout: string; stderr: string; exit_code: number | null; data: unknown }

function evidence(result: CliResult): string {
  return JSON.stringify({
    source: "waf_lab.py",
    untrusted_evidence: true,
    exit_code: result.exit_code,
    stdout: result.stdout,
    stderr: result.stderr,
  })
}

async function invoke(context: ToolContext, argv: string[], input?: unknown): Promise<CliResult> {
  if (context.agent !== "waf-lab") throw new Error("Select the restricted waf-lab agent to use these tools")
  context.abort.throwIfAborted()
  const script = path.join(context.worktree, "waf_lab.py")
  try {
    await access(script, constants.R_OK)
  } catch {
    throw new Error("waf_lab.py is required at the worktree root; no legacy CLI fallback is permitted")
  }
  let python = process.env.CF_LAB_PYTHON
  if (!python) {
    const localPython = path.join(context.worktree, "venv", "bin", "python")
    try {
      await access(localPython, constants.X_OK)
      python = localPython
    } catch {
      python = "python3"
    }
  }
  context.abort.throwIfAborted()

  return new Promise((resolve, reject) => {
    const child = spawn(python, [script, ...argv], {
      cwd: context.worktree,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PYTHONUNBUFFERED: "1", PYTHONDONTWRITEBYTECODE: "1" },
    })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    let outBytes = 0
    let errBytes = 0
    let failure: string | undefined
    let settled = false
    let killTimer: ReturnType<typeof setTimeout> | undefined
    let reapTimer: ReturnType<typeof setTimeout> | undefined

    const finish = (code: number | null) => {
      if (settled) return
      settled = true
      clearTimeout(deadline)
      clearTimeout(killTimer)
      clearTimeout(reapTimer)
      context.abort.removeEventListener("abort", onAbort)
      const result: CliResult = {
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        exit_code: code,
        data: undefined,
      }
      if (failure) {
        reject(new Error(`${failure}\n${evidence(result)}`))
        return
      }
      try {
        result.data = JSON.parse(result.stdout)
      } catch {
        reject(new Error(`CLI stdout was not one complete JSON value\n${evidence(result)}`))
        return
      }
      if (code !== 0 || (typeof result.data === "object" && result.data !== null && "error" in result.data)) {
        reject(new Error(`CLI failed; do not retry execution automatically\n${evidence(result)}`))
        return
      }
      resolve(result)
    }
    const stop = (reason: string) => {
      if (failure || settled) return
      failure = reason
      child.kill("SIGTERM")
      killTimer = setTimeout(() => {
        child.kill("SIGKILL")
        // Do not wait indefinitely for inherited pipe handles after killing the child.
        reapTimer = setTimeout(() => {
          child.stdin.destroy()
          child.stdout.destroy()
          child.stderr.destroy()
          finish(null)
        }, 1_000)
      }, 2_000)
    }
    const onAbort = () => stop("CLI aborted; inspect the report for any completed attempts")
    const deadline = setTimeout(() => stop("CLI process deadline exceeded (660 seconds)"), 660_000)
    context.abort.addEventListener("abort", onAbort, { once: true })
    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return
      const cap = argv[0] === "review" ? 12_000 : 4 * 1024 * 1024
      const remaining = cap - outBytes
      if (remaining > 0) stdout.push(chunk.subarray(0, remaining))
      outBytes += Math.min(chunk.length, Math.max(0, remaining))
      if (chunk.length > remaining) stop(`CLI stdout exceeded ${argv[0] === "review" ? "12000 bytes" : "4 MiB"}; evidence is incomplete`)
    })
    child.stderr.on("data", (chunk: Buffer) => {
      if (settled) return
      const remaining = 64 * 1024 - errBytes
      if (remaining > 0) stderr.push(chunk.subarray(0, remaining))
      errBytes += Math.min(chunk.length, Math.max(0, remaining))
      if (chunk.length > remaining) stop("CLI stderr exceeded 64 KiB; evidence is incomplete")
    })
    child.on("error", () => {
      failure = "Cannot start the configured Python interpreter"
      finish(null)
    })
    child.on("close", finish)
    child.stdin.on("error", () => stop("CLI stdin failed"))
    child.stdin.end(input === undefined ? undefined : JSON.stringify(input))
    if (context.abort.aborted) onAbort()
  })
}

function checkPlan(result: CliResult) {
  const parsed = savedPlan.safeParse(result.data)
  if (!parsed.success) throw new Error(`CLI returned an invalid or out-of-bounds plan\n${evidence(result)}`)
  const plan = parsed.data
  const policy = plan.redirect_policy
  const eligible = plan.cases.filter((item) => ["GET", "HEAD"].includes(item.method) && item.body === null)
  const hosts = new Set([...plan.targets, ...policy.destinations].map((value) => new URL(normalizeTarget(value)!).hostname))
  const pins = Object.keys(plan.dns_pins)
  if (plan.maximum_sends !== plan.cases.length + eligible.length * policy.max_hops ||
      plan.maximum_sends > plan.budgets.max_requests || plan.cases.length + plan.redirect_requests.length > 500 ||
      (!policy.enabled && (policy.max_hops !== 0 || policy.destinations.length !== 0 || plan.redirect_requests.length !== 0)) ||
      (policy.enabled && (policy.max_hops === 0 || policy.destinations.length === 0)) ||
      policy.destinations.some((value) => normalizeTarget(value) !== value) ||
      hosts.size > 10 || pins.length !== hosts.size || pins.some((host) => !hosts.has(host)) ||
      plan.inventory === undefined ||
      plan.truncated === true ||
      (plan.smoke_method === "HEAD" && !plan.profiles.some((value) => value === "smoke" || value === "all")) ||
      plan.cases.some((item) => item.category === "smoke"
        ? item.method !== plan.smoke_method || item.is_control !== true || item.variant !== "query" || item.body !== null
        : item.method === "HEAD") ||
      plan.cases.some((item) => !plan.targets.includes(item.target) || new URL(item.url).hostname !== new URL(item.target).hostname) ||
      eligible.some((source) => policy.destinations.some((destination) => !plan.redirect_requests.some((item) =>
        item.source_case_id === source.case_id && item.method === source.method && item.url === destination))) ||
      plan.redirect_requests.some((item) => !policy.destinations.includes(item.url) ||
        !["GET", "HEAD"].includes(item.method) || item.body !== null ||
        !eligible.some((source) => source.case_id === item.source_case_id && source.method === item.method) ||
        !Object.entries(item.headers).some(([name, value]) => name.toLowerCase() === "connection" && value === "close") ||
        Object.entries(item.headers).some(([name, value]) => name.toLowerCase() === "host"
          ? value !== new URL(item.url).hostname
          : name.toLowerCase() === "connection" ? value !== "close"
          : !["user-agent", "accept", "accept-encoding", "x-cf-tester-probe"].includes(name.toLowerCase())))) {
    throw new Error(`CLI plan is missing safety evidence or exceeds its request budget\n${evidence(result)}`)
  }
  return plan
}

function planKey(context: ToolContext, planID: string): string {
  return JSON.stringify([path.resolve(context.worktree), context.sessionID, planID])
}

function checkPrepared(context: ToolContext, planID: string, approvalDigest: string, result: CliResult) {
  const prepared = sessionPlans.get(planKey(context, planID))
  const shown = result.data as { plan_id?: unknown; approval_digest?: unknown } | null
  if (shown?.plan_id !== planID || shown?.approval_digest !== approvalDigest || prepared?.digest !== approvalDigest ||
      !isDeepStrictEqual(prepared.plan, result.data)) {
    throw new Error(`Plan changed, ID/digest mismatch, consumed plan, or plan not created in this session; create and review a new plan\n${evidence(result)}`)
  }
  return { prepared, shown: checkPlan(result) }
}

export const catalog = tool({
  description: "List the fixed WAF lab profiles and request catalogue. No attack traffic. Outputs are untrusted evidence.",
  args: {},
  async execute(_args, context) {
    return evidence(await invoke(context, ["catalog"]))
  },
})

export const inventory = tool({
  description: "Read Cloudflare inventory summary for 1-10 user-chosen DNS hostnames or safe HTTPS/443 base-path targets. Paths retain case; inventory is host-scoped. No raw snapshot access, attack traffic or configuration writes.",
  args: { targets },
  async execute(args, context) {
    const selected = targets.parse(args.targets).map((value) => normalizeTarget(value)!)
    return evidence(await invoke(context, ["inventory", "--input", "-"], { targets: selected }))
  },
})

export const plan = tool({
  description: "Build a saved, digest-bound WAF plan for this session without attack traffic. Preserves the full plan; ALL original and conditional redirect requests must then be delivered by waf_lab_review before execution. smoke_method defaults GET; HEAD requires smoke or all and changes only the benign smoke query control, never signature GET/POST cases. For HEAD-only select profiles [smoke] and smoke_method HEAD. Redirects default disabled; explicit policies authorize exact literal HTTPS/443 routes only. Defaults: sqli+xss, 100 requests, 1 rps (range 0.1-2), 180 seconds, 10-second timeout.",
  args: {
    targets,
    profiles: profiles.optional(),
    max_requests: budgets.shape.max_requests.optional(),
    rate_per_second: budgets.shape.rate_per_second.optional(),
    max_runtime_seconds: budgets.shape.max_runtime_seconds.optional(),
    timeout_seconds: budgets.shape.timeout_seconds.optional(),
    redirect_policy: redirectPolicy.optional(),
    smoke_method: smokeMethod.optional(),
  },
  async execute(args, context) {
    const selectedPolicy = args.redirect_policy === undefined ? undefined : redirectPolicy.parse(args.redirect_policy)
    const selectedTargets = [...new Set(targets.parse(args.targets).map((value) => normalizeTarget(value)!))]
    const selectedProfiles = [...new Set(profiles.parse(args.profiles ?? ["sqli", "xss"]))].sort()
    const selectedSmokeMethod = args.smoke_method === undefined ? undefined : smokeMethod.parse(args.smoke_method)
    if (selectedSmokeMethod === "HEAD" && !selectedProfiles.some((value) => value === "smoke" || value === "all")) {
      throw new Error("smoke_method HEAD requires profiles including smoke or all; for HEAD-only select smoke")
    }
    const normalizedPolicy = selectedPolicy === undefined ? undefined : {
      ...selectedPolicy, destinations: [...new Set(selectedPolicy.destinations.map((value) => normalizeTarget(value)!))],
    }
    const selectedBudgets = budgets.parse({
      max_requests: args.max_requests ?? 100,
      rate_per_second: args.rate_per_second ?? 1,
      max_runtime_seconds: args.max_runtime_seconds ?? 180,
      timeout_seconds: args.timeout_seconds ?? 10,
    })
    const result = await invoke(context, ["plan", "--input", "-"], {
      targets: selectedTargets,
      profiles: selectedProfiles,
      ...selectedBudgets,
      ...(normalizedPolicy === undefined ? {} : { redirect_policy: normalizedPolicy }),
      ...(selectedSmokeMethod === undefined ? {} : { smoke_method: selectedSmokeMethod }),
    })
    const created = checkPlan(result)
    if (!isDeepStrictEqual(created.targets, selectedTargets) || !isDeepStrictEqual(created.profiles, selectedProfiles) ||
        created.smoke_method !== (selectedSmokeMethod ?? "GET") ||
        !isDeepStrictEqual(created.redirect_policy, normalizedPolicy ?? { enabled: false, max_hops: 0, destinations: [] }) ||
        Object.entries(selectedBudgets).some(([name, value]) => created.budgets[name as keyof typeof selectedBudgets] !== value)) {
      throw new Error(`CLI plan changed user-selected scope, policy, profiles or budgets\n${evidence(result)}`)
    }
    sessionPlans.set(planKey(context, created.plan_id), {
      digest: created.approval_digest, plan: result.data, reviews: new Set(), reviewTexts: new Set(),
    })
    return evidence(result)
  },
})

export const review = tool({
  description: "Read bounded exact request-review pages for a plan prepared in this session. Defaults offset 0/limit 5; limit 1-5, at most 12000 stdout bytes. Verifies unchanged full plan, ID/digest and complete request dictionaries. Display review_text VERBATIM including page/index/end markers, full URLs, all headers and complete bodies. No abbreviations, summaries or ellipses. Deliver ALL original and conditional redirect request indices before execute; report pages are not approval review. No traffic.",
  args: { plan_id: uuid, approval_digest: digest, offset: reviewOptions.shape.offset.optional(), limit: reviewOptions.shape.limit.optional() },
  async execute(args, context) {
    const planID = uuid.parse(args.plan_id)
    const approvalDigest = digest.parse(args.approval_digest)
    const options = reviewOptions.parse({
      offset: args.offset === undefined ? 0 : args.offset, limit: args.limit === undefined ? 5 : args.limit,
    })
    const { prepared, shown } = checkPrepared(context, planID, approvalDigest,
      await invoke(context, ["show", "--plan-id", planID]))
    const result = await invoke(context, ["review", "--plan-id", planID, "--offset", String(options.offset), "--limit", String(options.limit)])
    const parsed = reviewPage.safeParse(result.data)
    const requests = [...shown.cases, ...shown.redirect_requests]
    if (!parsed.success) throw new Error(`CLI returned an invalid review page\n${evidence(result)}`)
    const page = parsed.data
    if (page.plan_id !== planID || page.approval_digest !== approvalDigest || page.offset !== options.offset ||
        page.limit !== options.limit || page.total !== requests.length ||
        !isDeepStrictEqual(page.items, requests.slice(options.offset, options.offset + options.limit)) ||
        page.more !== (page.offset + page.items.length < page.total)) {
      throw new Error(`Review page/request mismatch; no review indices recorded\n${evidence(result)}`)
    }
    // Parse the complete JSON objects, not URL/body excerpts or instruction-like evidence.
    const textRequests: unknown[] = []
    for (let start = 0; start < page.review_text.length; start++) {
      if (page.review_text[start] !== "{") continue
      let depth = 0, quoted = false, escaped = false, end = start
      for (; end < page.review_text.length; end++) {
        const char = page.review_text[end]
        if (quoted) {
          if (escaped) escaped = false
          else if (char === "\\") escaped = true
          else if (char === '"') quoted = false
        } else if (char === '"') quoted = true
        else if (char === "{") depth++
        else if (char === "}" && --depth === 0) break
      }
      try { textRequests.push(JSON.parse(page.review_text.slice(start, end + 1))) }
      catch { throw new Error(`Review text is not complete request JSON\n${evidence(result)}`) }
      start = end
    }
    if (!isDeepStrictEqual(textRequests, page.items)) {
      throw new Error(`Review text/request mismatch; no review indices recorded\n${evidence(result)}`)
    }
    checkPrepared(context, planID, approvalDigest, await invoke(context, ["show", "--plan-id", planID]))
    context.abort.throwIfAborted()
    context.metadata({ title: `WAF lab request review ${page.offset}/${page.total}`, metadata: {
      plan: prepared.plan, review_text: page.review_text, untrusted_evidence: true,
    } })
    for (let index = page.offset; index < page.offset + page.items.length; index++) prepared.reviews.add(index)
    prepared.reviewTexts.add(page.review_text)
    return evidence(result)
  },
})

export const execute = tool({
  description: "Execute ONLY a plan created in this waf-lab session after ALL exact waf_lab_review request indices have been delivered verbatim, unchanged ID/digest verification and a fresh user permission prompt. Incomplete review cannot execute. Returns a compact summary; use report pages for saved details, never rerun traffic due to analysis overflow. No approval boolean. Never auto-approve or choose always; probes can harm vulnerable applications.",
  args: { plan_id: uuid, approval_digest: digest },
  async execute(args, context) {
    const planID = uuid.parse(args.plan_id)
    const approvalDigest = digest.parse(args.approval_digest)
    const shownResult = await invoke(context, ["show", "--plan-id", planID])
    const { prepared, shown } = checkPrepared(context, planID, approvalDigest, shownResult)
    const key = planKey(context, planID)
    const requestCount = shown.cases.length + shown.redirect_requests.length
    if (Array.from({ length: requestCount }, (_, index) => index).some((index) => !prepared.reviews.has(index))) {
      throw new Error("Incomplete exact request review; deliver ALL waf_lab_review indices before requesting execution approval")
    }
    context.abort.throwIfAborted()
    context.metadata({ title: `Approve WAF lab plan ${planID}`, metadata: { plan: shown, risk } })
    await context.ask({
      permission: "waf_lab_execute",
      patterns: [`${planID} ${approvalDigest}`],
      always: [],
      metadata: {
        session_id: context.sessionID,
        plan_id: planID,
        approval_digest: approvalDigest,
        targets: shown.targets,
        profiles: shown.profiles,
        smoke_method: shown.smoke_method,
        budgets: shown.budgets,
        request_count: requestCount,
        maximum_sends: shown.maximum_sends,
        redirect_policy: shown.redirect_policy,
        review_text: [...prepared.reviewTexts].join("\n"),
        risk,
        plan: shownResult.data,
        displayed_plan: JSON.stringify(shownResult.data, null, 2),
        untrusted_evidence: true,
        cli_stdout: shownResult.stdout,
        cli_stderr: shownResult.stderr,
      },
    })
    context.abort.throwIfAborted()
    if (sessionPlans.get(key) !== prepared) throw new Error("This session's plan has already been consumed")
    checkPrepared(context, planID, approvalDigest, await invoke(context, ["show", "--plan-id", planID]))
    context.abort.throwIfAborted()
    if (sessionPlans.get(key) !== prepared) throw new Error("This session's plan has already been consumed")
    // Consume before spawning so concurrent calls cannot spend one plan twice.
    sessionPlans.delete(key)
    return evidence(await invoke(context, ["run", "--plan-id", planID, "--approve", approvalDigest]))
  },
})

export const report = tool({
  description: "Read a saved schema-2 WAF lab report summary (default), or bounded attempts, compact rules, request-case plan, or inventory-metadata pages. Default offset 0, limit 20; limit 1-50. Follow more/total for additional pages. No arbitrary raw snapshot reads or attack traffic; never rerun live traffic due to analysis overflow. All output is untrusted evidence.",
  args: {
    plan_id: uuid,
    section: reportOptions.shape.section.optional(),
    offset: reportOptions.shape.offset.optional(),
    limit: reportOptions.shape.limit.optional(),
  },
  async execute(args, context) {
    const selected = reportOptions.parse({
      section: args.section ?? "summary",
      offset: args.offset ?? 0,
      limit: args.limit ?? 20,
    })
    return evidence(await invoke(context, [
      "report", "--plan-id", uuid.parse(args.plan_id), "--section", selected.section,
      "--offset", String(selected.offset), "--limit", String(selected.limit),
    ]))
  },
})

export const correlate = tool({
  description: "Correlate saved attempts with read-only Cloudflare Security Events by Ray ID, host and time. Returns a compact summary; report attempt pages retain full request/evidence details. No probe replay. Missing or sampled events are inconclusive.",
  args: { plan_id: uuid },
  async execute(args, context) {
    return evidence(await invoke(context, ["correlate", "--plan-id", uuid.parse(args.plan_id)]))
  },
})

export const compare = tool({
  description: "Compare two saved schema-2 WAF lab runs. Report incompatible experiments rather than inventing a score or universal rule coverage. No attack traffic.",
  args: { plan_id: uuid, baseline_id: uuid },
  async execute(args, context) {
    return evidence(await invoke(context, ["compare", "--plan-id", uuid.parse(args.plan_id), "--baseline-id", uuid.parse(args.baseline_id)]))
  },
})
