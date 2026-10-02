// Intent classification for inbound SMS replies.
//
// Runs after strict pattern matching (YES / NO / CANCEL) and before the loose
// regex tiers. Returns one of: confirm, cancel, time_change (with hour/minute),
// handoff, unknown — or null if the API key isn't set or the call fails, in
// which case the caller continues with the existing pattern fallbacks.
//
// Model choice: claude-haiku-4-5 (cheap, fast, ~500-1000ms typical latency).
// Structured output is constrained server-side via output_config.format, so
// the response is always valid JSON matching the schema.
//
// Prompt caching: cache_control is placed on the system block. Haiku 4.5's
// minimum cacheable prefix is 4096 tokens — if the prompt + few-shots stay
// below that, caching silently becomes a no-op (no error, no savings).

const Anthropic = require("@anthropic-ai/sdk");

const apiKey = process.env.ANTHROPIC_API_KEY;
const client = apiKey ? new Anthropic({ apiKey, timeout: 5000 }) : null;

if (!apiKey) {
  console.warn("ANTHROPIC_API_KEY not set — LLM intent classification disabled, falling back to regex only.");
}

const SYSTEM_PROMPT = `You classify customer SMS replies to a boat reservation confirmation reminder.

The customer just received a message like:
"Hi <Name>! This is a reminder about your upcoming Reservation on <Day>, <Date> at <Time>. Reply YES to confirm, CANCEL to cancel, or send a new time."

Classify their reply into exactly one intent:

- confirm: They will keep the reservation as scheduled.
- cancel: They will NOT be coming. Cancel ALWAYS wins over confirm if both signals appear in the same message (e.g. "Sorry, I have to cancel, see you next time" = cancel — "see you" here is a goodbye, not a confirmation).
- time_change: They want to arrive at a different time. Extract the new time as 24-hour hour (0-23) and minute (0-59). "noon"=12:00, "midnight"=0:00. If the time has no am/pm and is ambiguous, pick the plausible DAYTIME boating interpretation (7-11 -> morning, 1-6 -> afternoon, 12 -> noon).
- running_late: They'll be late or want a different time but gave NO usable specific time ("running late", "be there a bit later", "in an hour", "need to push back"). The bot will ask them to reply with a new arrival time.
- handoff: Open-ended questions, requests for a human, availability inquiries, new bookings, anything outside the above. The bot can't answer; a team member will follow up.
- unknown: Truly unintelligible — random keystrokes, accidental sends, or no discernible intent.

Output JSON only, no commentary. For time_change include hour and minute; otherwise both null.

Examples:
"YES" -> {"intent":"confirm","hour":null,"minute":null}
"yes please" -> {"intent":"confirm","hour":null,"minute":null}
"sounds great, see you there" -> {"intent":"confirm","hour":null,"minute":null}
"we'll be there with bells on" -> {"intent":"confirm","hour":null,"minute":null}
"confirmed, thanks" -> {"intent":"confirm","hour":null,"minute":null}
"all good, count us in" -> {"intent":"confirm","hour":null,"minute":null}
"NO" -> {"intent":"cancel","hour":null,"minute":null}
"cancel please" -> {"intent":"cancel","hour":null,"minute":null}
"actually I need to cancel. see you next time" -> {"intent":"cancel","hour":null,"minute":null}
"sorry, something came up, won't make it" -> {"intent":"cancel","hour":null,"minute":null}
"can't make it today" -> {"intent":"cancel","hour":null,"minute":null}
"the kids are sick, we have to bail" -> {"intent":"cancel","hour":null,"minute":null}
"please remove us from the reservation" -> {"intent":"cancel","hour":null,"minute":null}
"7:30am" -> {"intent":"time_change","hour":7,"minute":30}
"can we move it to 2pm?" -> {"intent":"time_change","hour":14,"minute":0}
"how about noon" -> {"intent":"time_change","hour":12,"minute":0}
"running late, push to 10:15" -> {"intent":"time_change","hour":10,"minute":15}
"yes but at 8am please" -> {"intent":"time_change","hour":8,"minute":0}
"can we do 11" -> {"intent":"time_change","hour":11,"minute":0}
"930" -> {"intent":"time_change","hour":9,"minute":30}
"be there around 1030" -> {"intent":"time_change","hour":10,"minute":30}
"230" -> {"intent":"time_change","hour":14,"minute":30}
"midnight works" -> {"intent":"time_change","hour":0,"minute":0}
"do you have any boats available?" -> {"intent":"handoff","hour":null,"minute":null}
"I want to chat with a human" -> {"intent":"handoff","hour":null,"minute":null}
"can I bring my dog?" -> {"intent":"handoff","hour":null,"minute":null}
"what's the address?" -> {"intent":"handoff","hour":null,"minute":null}
"is there parking?" -> {"intent":"handoff","hour":null,"minute":null}
"can we add 2 more guests?" -> {"intent":"handoff","hour":null,"minute":null}
"I want to book another day" -> {"intent":"handoff","hour":null,"minute":null}
"do you allow coolers on board?" -> {"intent":"handoff","hour":null,"minute":null}
"running late" -> {"intent":"running_late","hour":null,"minute":null}
"gonna be a little behind this morning" -> {"intent":"running_late","hour":null,"minute":null}
"need to push to later" -> {"intent":"running_late","hour":null,"minute":null}
"can we come in an hour" -> {"intent":"running_late","hour":null,"minute":null}
"stuck in traffic" -> {"intent":"running_late","hour":null,"minute":null}
"asdfqwer" -> {"intent":"unknown","hour":null,"minute":null}
"sjsj" -> {"intent":"unknown","hour":null,"minute":null}
"😀" -> {"intent":"unknown","hour":null,"minute":null}`;

const SCHEMA = {
  type: "object",
  properties: {
    intent: {
      type: "string",
      enum: ["confirm", "cancel", "time_change", "running_late", "handoff", "unknown"],
    },
    hour: { type: ["integer", "null"] },
    minute: { type: ["integer", "null"] },
  },
  required: ["intent", "hour", "minute"],
  additionalProperties: false,
};

async function classifyIntent(inboundText) {
  if (!client) return null;
  if (!inboundText || !inboundText.trim()) return null;

  try {
    const response = await client.messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 100,
      system: [
        { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } },
      ],
      messages: [{ role: "user", content: inboundText }],
      output_config: { format: { type: "json_schema", schema: SCHEMA } },
    });

    const textBlock = response.content.find((b) => b.type === "text");
    if (!textBlock) return null;
    const parsed = JSON.parse(textBlock.text);

    // Belt-and-suspenders: hour/minute should only be present on time_change.
    // Defensive in case the schema constraint slips through.
    if (parsed.intent !== "time_change") {
      parsed.hour = null;
      parsed.minute = null;
    }
    return parsed;
  } catch (err) {
    console.error("Intent classification failed:", err.message);
    return null;
  }
}

module.exports = { classifyIntent };
