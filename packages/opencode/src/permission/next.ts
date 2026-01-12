import { Bus } from "@/bus"
import { BusEvent } from "@/bus/bus-event"
import { Config } from "@/config/config"
import { Identifier } from "@/id/id"
import { Instance } from "@/project/instance"
import { Storage } from "@/storage/storage"
import { fn } from "@/util/fn"
import { Log } from "@/util/log"
import { Wildcard } from "@/util/wildcard"
import { generateText } from "ai"
import { Provider } from "@/provider/provider"
import path from "path"
import fs from "fs/promises"
import z from "zod"

export namespace PermissionNext {
  const log = Log.create({ service: "permission" })

  export const Action = z.enum(["allow", "deny", "ask"]).meta({
    ref: "PermissionAction",
  })
  export type Action = z.infer<typeof Action>

  export const Rule = z
    .object({
      permission: z.string(),
      pattern: z.string(),
      action: Action,
    })
    .meta({
      ref: "PermissionRule",
    })
  export type Rule = z.infer<typeof Rule>

  export const Ruleset = Rule.array().meta({
    ref: "PermissionRuleset",
  })
  export type Ruleset = z.infer<typeof Ruleset>

  export function fromConfig(permission: Config.Permission) {
    const ruleset: Ruleset = []
    for (const [key, value] of Object.entries(permission)) {
      if (typeof value === "string") {
        ruleset.push({
          permission: key,
          action: value,
          pattern: "*",
        })
        continue
      }
      ruleset.push(...Object.entries(value).map(([pattern, action]) => ({ permission: key, pattern, action })))
    }
    return ruleset
  }

  export function merge(...rulesets: Ruleset[]): Ruleset {
    return rulesets.flat()
  }

  export const Request = z
    .object({
      id: Identifier.schema("permission"),
      sessionID: Identifier.schema("session"),
      permission: z.string(),
      patterns: z.string().array(),
      metadata: z.record(z.string(), z.any()),
      always: z.string().array(),
      tool: z
        .object({
          messageID: z.string(),
          callID: z.string(),
        })
        .optional(),
    })
    .meta({
      ref: "PermissionRequest",
    })

  export type Request = z.infer<typeof Request>

  export const Reply = z.enum(["once", "always", "reject"])
  export type Reply = z.infer<typeof Reply>

  export const Approval = z.object({
    projectID: z.string(),
    patterns: z.string().array(),
  })

  export const Event = {
    Asked: BusEvent.define("permission.asked", Request),
    Replied: BusEvent.define(
      "permission.replied",
      z.object({
        sessionID: z.string(),
        requestID: z.string(),
        reply: Reply,
      }),
    ),
  }

  const state = Instance.state(async () => {
    const projectID = Instance.project.id
    const stored = await Storage.read<Ruleset>(["permission", projectID]).catch(() => [] as Ruleset)

    const pending: Record<
      string,
      {
        info: Request
        resolve: () => void
        reject: (e: any) => void
      }
    > = {}

    return {
      pending,
      approved: stored,
    }
  })

  export const ask = fn(
    Request.partial({ id: true }).extend({
      ruleset: Ruleset,
    }),
    async (input) => {
      const s = await state()
      const { ruleset, ...request } = input

      // Check if LLM permission check is enabled
      const config = await Config.get()
      const llmCheckEnabled = config.llmPermissionCheck?.enabled === true

      for (const pattern of request.patterns ?? []) {
        const rule = evaluate(request.permission, pattern, ruleset, s.approved)
        log.info("evaluated", { permission: request.permission, pattern, action: rule })

        if (rule.action === "deny")
          throw new DeniedError(ruleset.filter((r) => Wildcard.match(request.permission, r.permission)))

        // If LLM check is enabled and the rule allows, do an additional LLM check
        if (llmCheckEnabled && rule.action === "allow") {
          const llmResult = await checkWithLLM({
            permission: request.permission,
            patterns: request.patterns,
            metadata: request.metadata,
            currentDirectory: Instance.directory,
          })

          log.info("LLM check decision", {
            permission: request.permission,
            pattern,
            llmAction: llmResult.action,
            reason: llmResult.reason,
          })

          if (llmResult.action === "deny") {
            throw new LLMDeniedError(llmResult.reason)
          }

          if (llmResult.action === "ask") {
            const id = input.id ?? Identifier.ascending("permission")
            return new Promise<void>((resolve, reject) => {
              const info: Request = {
                id,
                ...request,
                metadata: {
                  ...request.metadata,
                  llmReason: llmResult.reason,
                },
              }
              s.pending[id] = {
                info,
                resolve,
                reject,
              }
              Bus.publish(Event.Asked, info)
            })
          }

          // If llmResult.action === "allow", continue
        }

        if (rule.action === "ask") {
          const id = input.id ?? Identifier.ascending("permission")
          return new Promise<void>((resolve, reject) => {
            const info: Request = {
              id,
              ...request,
            }
            s.pending[id] = {
              info,
              resolve,
              reject,
            }
            Bus.publish(Event.Asked, info)
          })
        }
        if (rule.action === "allow") continue
      }
    },
  )

  export const reply = fn(
    z.object({
      requestID: Identifier.schema("permission"),
      reply: Reply,
      message: z.string().optional(),
    }),
    async (input) => {
      const s = await state()
      const existing = s.pending[input.requestID]
      if (!existing) return
      delete s.pending[input.requestID]
      Bus.publish(Event.Replied, {
        sessionID: existing.info.sessionID,
        requestID: existing.info.id,
        reply: input.reply,
      })
      if (input.reply === "reject") {
        existing.reject(input.message ? new CorrectedError(input.message) : new RejectedError())
        // Reject all other pending permissions for this session
        const sessionID = existing.info.sessionID
        for (const [id, pending] of Object.entries(s.pending)) {
          if (pending.info.sessionID === sessionID) {
            delete s.pending[id]
            Bus.publish(Event.Replied, {
              sessionID: pending.info.sessionID,
              requestID: pending.info.id,
              reply: "reject",
            })
            pending.reject(new RejectedError())
          }
        }
        return
      }
      if (input.reply === "once") {
        existing.resolve()
        return
      }
      if (input.reply === "always") {
        for (const pattern of existing.info.always) {
          s.approved.push({
            permission: existing.info.permission,
            pattern,
            action: "allow",
          })
        }

        existing.resolve()

        const sessionID = existing.info.sessionID
        for (const [id, pending] of Object.entries(s.pending)) {
          if (pending.info.sessionID !== sessionID) continue
          const ok = pending.info.patterns.every(
            (pattern) => evaluate(pending.info.permission, pattern, s.approved).action === "allow",
          )
          if (!ok) continue
          delete s.pending[id]
          Bus.publish(Event.Replied, {
            sessionID: pending.info.sessionID,
            requestID: pending.info.id,
            reply: "always",
          })
          pending.resolve()
        }

        // TODO: we don't save the permission ruleset to disk yet until there's
        // UI to manage it
        // await Storage.write(["permission", Instance.project.id], s.approved)
        return
      }
    },
  )

  export function evaluate(permission: string, pattern: string, ...rulesets: Ruleset[]): Rule {
    const merged = merge(...rulesets)
    log.info("evaluate", { permission, pattern, ruleset: merged })
    const match = merged.findLast(
      (rule) => Wildcard.match(permission, rule.permission) && Wildcard.match(pattern, rule.pattern),
    )
    return match ?? { action: "ask", permission, pattern: "*" }
  }

  /**
   * Detect if a bash command is executing a script and extract the script path
   */
  async function detectScriptExecution(
    patterns: string[],
    currentDirectory: string,
  ): Promise<{ isScript: boolean; scriptPath?: string; scriptContent?: string }> {
    for (const pattern of patterns) {
      // Match common script execution patterns
      const scriptPatterns = [
        /^(bash|sh)\s+(.+\.sh)/i, // bash script.sh, sh script.sh
        /^(python|python3)\s+(.+\.py)/i, // python script.py
        /^(node|nodejs)\s+(.+\.js)/i, // node script.js
        /^(ruby)\s+(.+\.rb)/i, // ruby script.rb
        /^(perl)\s+(.+\.pl)/i, // perl script.pl
        /^\.\/(.+\.sh)/i, // ./script.sh
        /^\.\/(.+\.py)/i, // ./script.py
        /^\.\/(.+\.js)/i, // ./script.js
      ]

      for (const regex of scriptPatterns) {
        const match = pattern.match(regex)
        if (match) {
          // Extract script path (either from group 2 or group 1)
          const scriptPath = match[2] || match[1]

          try {
            // Resolve absolute path
            const absolutePath = path.isAbsolute(scriptPath)
              ? scriptPath
              : path.join(currentDirectory, scriptPath)

            // Try to read the script content
            const scriptContent = await fs.readFile(absolutePath, "utf-8")
            log.info("Detected script execution", { scriptPath: absolutePath })

            return {
              isScript: true,
              scriptPath: absolutePath,
              scriptContent,
            }
          } catch (error) {
            // Script file doesn't exist or can't be read
            log.warn("Cannot read script file", { scriptPath, error })
            return { isScript: true, scriptPath }
          }
        }
      }
    }

    return { isScript: false }
  }

  /**
   * Use LLM to check if the operation should be allowed based on security principles:
   * 1. Cannot modify or delete anything outside the current directory
   * 2. All read operations are allowed
   * 3. Scripts and commands must follow the above rules
   */
  export async function checkWithLLM(request: {
    permission: string
    patterns: string[]
    metadata: Record<string, any>
    currentDirectory: string
  }): Promise<{ action: Action; reason: string }> {
    try {
      const config = await Config.get()

      // Check if LLM permission check is enabled
      if (!config.llmPermissionCheck?.enabled) {
        return { action: "allow", reason: "LLM permission check is disabled" }
      }

      // Get the model for LLM permission check
      const modelID = config.llmPermissionCheck?.model || config.model
      if (!modelID) {
        log.warn("No model specified for LLM permission check, skipping")
        return { action: "allow", reason: "No model configured for LLM check" }
      }

      const model = await Provider.getLanguage({ id: modelID, providerID: config.provider || "anthropic" })

      // Detect if this is a script execution and try to read the script content
      const scriptInfo = await detectScriptExecution(request.patterns, request.currentDirectory)

      let scriptSection = ""
      if (scriptInfo.isScript && scriptInfo.scriptContent) {
        scriptSection = `

**IMPORTANT: Script Execution Detected**
The command is executing a script file. Here is the script content:

\`\`\`
${scriptInfo.scriptContent}
\`\`\`

You MUST analyze ALL commands in this script and ensure NONE of them:
- Modify or delete files outside the current directory (${request.currentDirectory})
- Execute dangerous operations like system-wide changes
- Call other scripts or tools that might violate the security principles

If ANY command in the script violates the security principles, return "deny".
If the script is safe (only reads or modifies files inside current directory), return "allow".
If uncertain, return "ask".`
      } else if (scriptInfo.isScript && !scriptInfo.scriptContent) {
        scriptSection = `

**WARNING: Script Execution Detected**
The command is executing a script file (${scriptInfo.scriptPath}), but the script content cannot be read.
This could be risky because we cannot verify what the script will do.
Consider returning "ask" or "deny" unless you are certain this is safe.`
      }

      const prompt = `You are a security checker for a coding assistant. Your role is to determine if an operation should be allowed based on these strict security principles:

1. **Modification Rule**: DENY any operations that modify or delete files/directories outside the current working directory
2. **Read Rule**: ALLOW all read operations (reading files, listing directories, searching, etc.)
3. **Command Rule**: For bash commands and scripts, they must follow rules 1 and 2
4. **Script Rule**: When executing scripts, analyze the ENTIRE script content to ensure all commands follow the above rules
5. **Tool Rule**: For executing tools/binaries, use conservative approach - if unsure, choose "ask"

**Current Working Directory**: ${request.currentDirectory}

**Operation Details**:
- Permission Type: ${request.permission}
- Patterns: ${request.patterns.join(", ")}
- Metadata: ${JSON.stringify(request.metadata, null, 2)}${scriptSection}

**Your Task**: Analyze this operation and respond with ONLY a JSON object in this exact format:
{
  "action": "allow" | "deny" | "ask",
  "reason": "Brief explanation of your decision"
}

**Decision Logic**:
- If it's a read operation (read, grep, glob, list, etc.) → "allow"
- If it's modifying/deleting INSIDE current directory → "allow"
- If it's modifying/deleting OUTSIDE current directory → "deny"
- If it's a bash command, analyze what it does:
  - Commands like "cat", "ls", "grep" → "allow"
  - Commands like "rm", "mv", "cp" outside current dir → "deny"
  - Commands like "rm", "mv", "cp" inside current dir → "allow"
  - Script execution with safe content → "allow"
  - Script execution with unsafe content → "deny"
  - Script execution with unreadable content → "ask"
  - Tool/binary execution with unknown behavior → "ask"
  - If unclear → "ask"
- If uncertain about the safety → "ask"

Respond with ONLY the JSON object, no other text.`

      const result = await generateText({
        model,
        prompt,
        maxTokens: 1000, // Increased for script analysis
      })

      const response = JSON.parse(result.text.trim()) as { action: Action; reason: string }

      log.info("LLM permission check result", {
        permission: request.permission,
        patterns: request.patterns,
        isScript: scriptInfo.isScript,
        action: response.action,
        reason: response.reason,
      })

      return response
    } catch (error) {
      log.error("Error in LLM permission check", { error })
      // On error, default to asking the user
      return { action: "ask", reason: `LLM check failed: ${error}` }
    }
  }

  const EDIT_TOOLS = ["edit", "write", "patch", "multiedit"]

  export function disabled(tools: string[], ruleset: Ruleset): Set<string> {
    const result = new Set<string>()
    for (const tool of tools) {
      const permission = EDIT_TOOLS.includes(tool) ? "edit" : tool

      const rule = ruleset.findLast((r) => Wildcard.match(permission, r.permission))
      if (!rule) continue
      if (rule.pattern === "*" && rule.action === "deny") result.add(tool)
    }
    return result
  }

  /** User rejected without message - halts execution */
  export class RejectedError extends Error {
    constructor() {
      super(`The user rejected permission to use this specific tool call.`)
    }
  }

  /** User rejected with message - continues with guidance */
  export class CorrectedError extends Error {
    constructor(message: string) {
      super(`The user rejected permission to use this specific tool call with the following feedback: ${message}`)
    }
  }

  /** Auto-rejected by config rule - halts execution */
  export class DeniedError extends Error {
    constructor(public readonly ruleset: Ruleset) {
      super(
        `The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules ${JSON.stringify(ruleset)}`,
      )
    }
  }

  /** Auto-rejected by LLM security check - halts execution */
  export class LLMDeniedError extends Error {
    constructor(reason: string) {
      super(
        `The LLM security checker has determined that this operation violates security principles. Reason: ${reason}`,
      )
    }
  }

  export async function list() {
    return state().then((x) => Object.values(x.pending).map((x) => x.info))
  }
}
