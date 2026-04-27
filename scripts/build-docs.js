#!/usr/bin/env node
/**
 * build-docs.js
 *
 * Reads the TypeDoc JSON output and transforms it into the standard
 * sdk-docs.json format consumed by the docs renderer.
 *
 * Usage:
 *   node scripts/build-docs.js
 *   node scripts/build-docs.js --input docs/typedoc-output.json --output docs/sdk-docs.json
 *
 * The standard format is renderer-agnostic and shared across all Auth0 SDK docs.
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const getArg = (flag) => {
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : null;
};

const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dir, "..");

const INPUT = resolve(ROOT, getArg("--input") ?? "docs/typedoc-output.json");
const OUTPUT = resolve(ROOT, getArg("--output") ?? "docs/sdk-docs.json");

// ---------------------------------------------------------------------------
// Load TypeDoc JSON
// ---------------------------------------------------------------------------

const typedoc = JSON.parse(readFileSync(INPUT, "utf8"));

// ---------------------------------------------------------------------------
// Helpers — navigating the TypeDoc reflection tree
// ---------------------------------------------------------------------------

/** Recursively find all reflections matching a predicate */
function findAll(node, predicate, results = []) {
  if (!node || typeof node !== "object") return results;
  if (predicate(node)) results.push(node);
  for (const child of node.children ?? []) findAll(child, predicate, results);
  return results;
}

/** Find one reflection by name + kind bitmask */
function findOne(node, name, kindBit) {
  return findAll(node, (r) => r.name === name && (r.kind & kindBit) !== 0)[0] ?? null;
}

/**
 * TypeDoc kind constants (bitmask)
 * https://typedoc.org/api/enums/Models.ReflectionKind.html
 */
const Kind = {
  Module: 2,
  Class: 128,
  Interface: 256,
  TypeAlias: 2097152,    // 0x200000 — also seen as 4194304 in newer TypeDoc versions
  TypeAlias2: 4194304,   // 0x400000 — newer TypeDoc
  Enum: 8,
  EnumMember: 16,
  Function: 64,
  Method: 2048,
  Property: 1024,
  Accessor: 262144,
  Variable: 32,
  Constructor: 512,
};

/** Map a TypeDoc kind to our schema kind string */
function toKind(kindBit) {
  const map = {
    [Kind.Class]: "class",
    [Kind.Interface]: "interface",
    [Kind.TypeAlias]: "type",
    [Kind.TypeAlias2]: "type",
    [Kind.Enum]: "enum",
    [Kind.EnumMember]: "enum-member",
    [Kind.Function]: "function",
    [Kind.Method]: "method",
    [Kind.Property]: "property",
    [Kind.Accessor]: "property",
    [Kind.Variable]: "constant",
    [Kind.Constructor]: "constructor",
  };
  return map[kindBit] ?? "unknown";
}

/** Slugify a name for use as a page id */
function slug(name) {
  return name
    .replace(/([a-z])([A-Z])/g, "$1-$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1-$2")
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

// ---------------------------------------------------------------------------
// Text extraction from TypeDoc comment shapes
// ---------------------------------------------------------------------------

function extractSummary(comment) {
  if (!comment) return "";
  return (comment.summary ?? [])
    .map((part) => part.text ?? "")
    .join("")
    .trim();
}

function extractBlockTag(comment, tagName) {
  if (!comment) return [];
  return (comment.blockTags ?? []).filter((t) => t.tag === tagName);
}

function blockTagText(tag) {
  return (tag.content ?? [])
    .map((p) => p.text ?? "")
    .join("")
    .trim();
}

/** Extract all @throws tags as { type, code, description } */
function extractThrows(comment) {
  return extractBlockTag(comment, "@throws").map((tag) => {
    const raw = blockTagText(tag);
    // Pattern: "`ErrorClass` (code `"code_value"`) description"
    const typeMatch = raw.match(/^`([^`]+)`/);
    const codeMatch = raw.match(/\(code `"([^"]+)"`\)/);
    const description = raw
      .replace(/^`[^`]+`/, "")
      .replace(/\(code `"[^"]+"`\)/, "")
      .trim()
      .replace(/^[-–]\s*/, "");
    return {
      type: typeMatch ? typeMatch[1] : raw,
      ...(codeMatch ? { code: codeMatch[1] } : {}),
      description,
    };
  });
}

/** Extract @example tags as { title, language, code } */
function extractExamples(comment) {
  return extractBlockTag(comment, "@example").map((tag) => {
    const raw = blockTagText(tag);
    // First line may be the title (non-code line before the fence)
    const lines = raw.split("\n");
    let title = "";
    let body = raw;

    if (lines[0] && !lines[0].startsWith("```")) {
      title = lines[0].trim();
      body = lines.slice(1).join("\n").trim();
    }

    const fenceMatch = body.match(/^```(\w*)\n([\s\S]*?)```$/m);
    if (fenceMatch) {
      return { title, language: fenceMatch[1] || "ts", code: fenceMatch[2].trimEnd() };
    }
    return { title, language: "ts", code: body };
  });
}

/** Render a TypeDoc type node as a human-readable string */
function typeToString(typeNode) {
  if (!typeNode) return "unknown";
  switch (typeNode.type) {
    case "intrinsic":
      return typeNode.name;
    case "reference":
      if (typeNode.typeArguments?.length) {
        return `${typeNode.name}<${typeNode.typeArguments.map(typeToString).join(", ")}>`;
      }
      return typeNode.name;
    case "union":
      return typeNode.types.map(typeToString).join(" | ");
    case "intersection":
      return typeNode.types.map(typeToString).join(" & ");
    case "array":
      return `${typeToString(typeNode.elementType)}[]`;
    case "tuple":
      return `[${(typeNode.elements ?? []).map(typeToString).join(", ")}]`;
    case "literal":
      return JSON.stringify(typeNode.value);
    case "reflection":
      return "{ ... }";
    case "conditional":
      return `${typeToString(typeNode.checkType)} extends ${typeToString(typeNode.extendsType)} ? ${typeToString(typeNode.trueType)} : ${typeToString(typeNode.falseType)}`;
    case "predicate":
      return `${typeNode.name} is ${typeToString(typeNode.targetType)}`;
    case "typeOperator":
      return `${typeNode.operator} ${typeToString(typeNode.target)}`;
    case "query":
      return `typeof ${typeToString(typeNode.queryType)}`;
    case "inferred":
      return `infer ${typeNode.name}`;
    case "mapped":
      return "{ [K in ...]: ... }";
    case "optional":
      return `${typeToString(typeNode.elementType)}?`;
    case "rest":
      return `...${typeToString(typeNode.elementType)}`;
    case "named-tuple-member":
      return `${typeNode.name}: ${typeToString(typeNode.element)}`;
    case "template-literal":
      return "`..template..`";
    default:
      return typeNode.name ?? typeNode.type ?? "unknown";
  }
}

/** Build a human-readable signature string for a callable */
function buildSignature(reflection, sigNode) {
  if (!sigNode) return reflection.name;
  const params = (sigNode.parameters ?? [])
    .map((p) => {
      const optional = p.flags?.isOptional ? "?" : "";
      return `${p.name}${optional}: ${typeToString(p.type)}`;
    })
    .join(", ");
  const ret = typeToString(sigNode.type);
  return `${reflection.name}(${params}): ${ret}`;
}

// ---------------------------------------------------------------------------
// Property extraction (for interfaces and class-level properties)
// ---------------------------------------------------------------------------

function extractProperty(propReflection) {
  const comment = propReflection.comment;
  const typeStr = typeToString(propReflection.type);
  const defaultTag = extractBlockTag(comment, "@default")[0];
  const seeTag = extractBlockTag(comment, "@see").map(blockTagText);

  return {
    name: propReflection.name,
    type: typeStr,
    optional: propReflection.flags?.isOptional ?? false,
    description: extractSummary(comment),
    ...(defaultTag ? { default: blockTagText(defaultTag) } : {}),
    ...(seeTag.length ? { see: seeTag } : {}),
  };
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------

/**
 * Build a page for a callable (function, method, accessor/getter).
 * `parentName` is filled in when the callable belongs to a class.
 */
function buildCallablePage(reflection, section, parentName = null) {
  const sigNode =
    reflection.signatures?.[0] ??
    reflection.getSignature ??
    null;

  const comment = sigNode?.comment ?? reflection.comment;
  const description = extractSummary(comment);
  const throws = extractThrows(comment);
  const examples = extractExamples(comment);

  // Parameters come from the signature node
  const parameters = (sigNode?.parameters ?? []).map((p) => ({
    name: p.name,
    type: typeToString(p.type),
    optional: p.flags?.isOptional ?? false,
    ...(p.defaultValue ? { default: p.defaultValue } : {}),
    description: extractSummary(p.comment),
  }));

  const returns = sigNode
    ? {
        type: typeToString(sigNode.type),
        description: blockTagText(
          extractBlockTag(comment, "@returns")[0] ?? { content: [] }
        ),
      }
    : null;

  return {
    id: slug(reflection.name),
    title: reflection.name,
    kind: toKind(reflection.kind),
    section,
    ...(parentName ? { memberOf: parentName } : {}),
    description,
    signature: buildSignature(reflection, sigNode),
    parameters,
    ...(returns ? { returns } : {}),
    ...(throws.length ? { throws } : {}),
    ...(examples.length ? { examples } : {}),
  };
}

/**
 * Build a page for an interface or type alias.
 * Properties are listed inline.
 */
function buildTypePage(reflection, section) {
  const comment = reflection.comment;
  const description = extractSummary(comment);
  const examples = extractExamples(comment);
  const seeTag = extractBlockTag(comment, "@see").map(blockTagText);

  // Collect properties from children (Interface) or declaration (TypeAlias)
  const rawProps =
    reflection.children?.filter(
      (c) => c.kind === Kind.Property || c.kind === Kind.Accessor
    ) ?? [];

  const properties = rawProps.map(extractProperty);

  return {
    id: slug(reflection.name),
    title: reflection.name,
    kind: toKind(reflection.kind),
    section,
    description,
    ...(properties.length ? { properties } : {}),
    ...(examples.length ? { examples } : {}),
    ...(seeTag.length ? { see: seeTag } : {}),
  };
}

/**
 * Build a page for an enum.
 * Members are listed inline.
 */
function buildEnumPage(reflection, section) {
  const comment = reflection.comment;
  const members = (reflection.children ?? []).map((m) => ({
    name: m.name,
    value: m.type?.value ?? m.defaultValue ?? null,
    description: extractSummary(m.comment),
  }));

  return {
    id: slug(reflection.name),
    title: reflection.name,
    kind: "enum",
    section,
    description: extractSummary(comment),
    members,
  };
}

/**
 * Build a page for the Auth0Client class itself.
 * Lists constructor params and documents the built-in routes.
 * Individual method pages are separate — this page is the "overview / setup" page.
 */
function buildClassPage(reflection, section) {
  const comment = reflection.comment;
  const description = extractSummary(comment);
  const examples = extractExamples(comment);

  const ctorReflection = reflection.children?.find(
    (c) => c.kind === Kind.Constructor
  );
  const ctorSig = ctorReflection?.signatures?.[0];
  const constructorParams = (ctorSig?.parameters ?? []).map((p) => ({
    name: p.name,
    type: typeToString(p.type),
    optional: p.flags?.isOptional ?? false,
    description: extractSummary(p.comment),
  }));

  return {
    id: slug(reflection.name),
    title: reflection.name,
    kind: "class",
    section,
    description,
    ...(constructorParams.length
      ? {
          constructor: {
            signature: `new ${reflection.name}(${constructorParams
              .map((p) => `${p.name}${p.optional ? "?" : ""}: ${p.type}`)
              .join(", ")})`,
            parameters: constructorParams,
          },
        }
      : {}),
    ...(examples.length ? { examples } : {}),
  };
}

/** Build a page for a top-level constant or variable */
function buildConstantPage(reflection, section) {
  const comment = reflection.comment;
  return {
    id: slug(reflection.name),
    title: reflection.name,
    kind: "constant",
    section,
    description: extractSummary(comment),
    type: typeToString(reflection.type),
  };
}

// ---------------------------------------------------------------------------
// Navigation configuration
// ---------------------------------------------------------------------------

/**
 * Describes how to build the navigation and which symbols belong to each section.
 * Edit this object to add/remove sections or reorder items.
 *
 * Each entry in `items` is either:
 *   - a string matching a reflection name (order preserved), or
 *   - { name, title } to override the display title
 *
 * `source` tells the builder which module to search in.
 * If omitted, searches the entire TypeDoc tree.
 */
const NAV_CONFIG = [
  {
    section: "Initialisation",
    items: [{ name: "Auth0Client", title: "Auth0Client" }],
  },
  {
    section: "Auth0Client",
    // Auth0Client methods — each becomes its own page
    memberOf: "Auth0Client",
    items: [
      "middleware",
      "getSession",
      "getAccessToken",
      "getAccessTokenForConnection",
      "updateSession",
      "customTokenExchange",
      "mfa",
      "withPageAuthRequired",
      "withApiAuthRequired",
      "startInteractiveLogin",
      "getTokenByBackchannelAuth",
      "connectAccount",
      "createFetcher",
    ],
  },
  {
    section: "Server",
    items: [
      "AbstractSessionStore",
      "Auth0ClientOptions",
      "PagesRouterRequest",
      "PagesRouterResponse",
      "BeforeSessionSavedHook",
      "OnCallbackHook",
      "OnCallbackContext",
      "RoutesOptions",
      "Routes",
      "SessionCookieOptions",
      "SessionConfiguration",
      "SessionStoreOptions",
      "SessionData",
      "SessionDataStore",
      "User",
      "LogoutToken",
      "LogoutStrategy",
      "StartInteractiveLoginOptions",
      "AuthorizationParameters",
      "GetAccessTokenOptions",
      "AccessTokenForConnectionOptions",
      "ConnectionTokenSet",
      "CustomTokenExchangeOptions",
      "CustomTokenExchangeResponse",
      "BackchannelAuthenticationOptions",
      "BackchannelAuthenticationResponse",
      "AuthorizationDetails",
      "ConnectAccountOptions",
      "MfaClient",
      "Authenticator",
      "ChallengeResponse",
      "EnrollOptions",
      "EnrollOtpOptions",
      "EnrollOobOptions",
      "EnrollmentResponse",
      "VerifyMfaOptions",
      "VerifyMfaOptionsBase",
      "VerifyMfaWithOtpOptions",
      "VerifyMfaWithOobOptions",
      "VerifyMfaWithRecoveryCodeOptions",
      "MfaVerifyResponse",
      "DomainResolver",
      "DiscoveryCacheOptions",
      "DpopKeyPair",
      "DpopOptions",
      "RetryConfig",
      "SUBJECT_TOKEN_TYPES",
      "GRANT_TYPE_CUSTOM_TOKEN_EXCHANGE",
      "DEFAULT_ID_TOKEN_CLAIMS",
      "filterDefaultIdTokenClaims",
      "generateDpopKeyPair",
    ],
  },
  {
    section: "Client",
    items: [
      "Auth0Provider",
      "useUser",
      "getAccessToken",
      "withPageAuthRequired",
      "UserProfile",
      "UserContext",
      "UserProviderProps",
    ],
  },
  {
    section: "Testing",
    items: ["generateSessionCookie"],
  },
];

// ---------------------------------------------------------------------------
// Main builder
// ---------------------------------------------------------------------------

function build() {
  const pages = {};
  const navigation = [];

  // Index all reflections by name for quick lookup
  const byName = new Map();
  function index(node) {
    if (!node || typeof node !== "object") return;
    if (node.name && node.kind) {
      if (!byName.has(node.name)) byName.set(node.name, []);
      byName.get(node.name).push(node);
    }
    for (const child of node.children ?? []) index(child);
  }
  index(typedoc);

  // Also index class members directly
  const classMemberByName = new Map();
  const auth0ClientReflection = findOne(typedoc, "Auth0Client", Kind.Class);
  if (auth0ClientReflection) {
    for (const child of auth0ClientReflection.children ?? []) {
      classMemberByName.set(child.name, child);
    }
  }

  function resolveReflection(name, memberOf) {
    // If looking for a class member, search the class children first
    if (memberOf === "Auth0Client") {
      const member = classMemberByName.get(name);
      if (member) return member;
    }
    const candidates = byName.get(name) ?? [];
    // Prefer the one that is NOT @internal
    return (
      candidates.find(
        (r) =>
          !r.comment?.modifierTags?.includes("@internal") &&
          r.flags?.isPrivate !== true
      ) ?? candidates[0] ?? null
    );
  }

  function buildPage(reflection, section, memberOf) {
    if (!reflection) return null;

    const k = reflection.kind;

    if (k === Kind.Class) return buildClassPage(reflection, section);

    if (
      k === Kind.Method ||
      k === Kind.Function ||
      k === Kind.Accessor
    )
      return buildCallablePage(reflection, section, memberOf ?? null);

    if (k === Kind.Interface || k === Kind.TypeAlias || k === Kind.TypeAlias2)
      return buildTypePage(reflection, section);

    if (k === Kind.Enum) return buildEnumPage(reflection, section);

    if (k === Kind.Variable || k === Kind.Property)
      return buildConstantPage(reflection, section);

    // Fallback — treat as callable if it has signatures
    if (reflection.signatures?.length)
      return buildCallablePage(reflection, section, memberOf ?? null);

    return buildTypePage(reflection, section);
  }

  for (const navEntry of NAV_CONFIG) {
    const { section, items, memberOf } = navEntry;
    const navItems = [];

    for (const item of items) {
      const name = typeof item === "string" ? item : item.name;
      const title = typeof item === "string" ? item : item.title;

      const reflection = resolveReflection(name, memberOf);
      if (!reflection) {
        console.warn(`[build-docs] Could not find reflection for "${name}" in section "${section}"`);
        continue;
      }

      const page = buildPage(reflection, section, memberOf);
      if (!page) {
        console.warn(`[build-docs] Could not build page for "${name}"`);
        continue;
      }

      // Use the name as-is for id to keep it predictable for the renderer
      const pageId = slug(name);
      // If there is a collision (e.g. getAccessToken exists in both Client and Auth0Client),
      // prefix with section to disambiguate
      const finalId = pages[pageId]
        ? `${slug(section)}-${pageId}`
        : pageId;

      page.id = finalId;
      page.title = title;
      pages[finalId] = page;
      navItems.push({ id: finalId, title, kind: page.kind });
    }

    if (navItems.length) {
      navigation.push({ section, items: navItems });
    }
  }

  // Read package meta from package.json
  let pkg = { name: "unknown", version: "0.0.0" };
  try {
    pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8"));
  } catch {}

  const output = {
    meta: {
      package: pkg.name,
      version: pkg.version,
      generatedAt: new Date().toISOString(),
    },
    navigation,
    pages,
  };

  writeFileSync(OUTPUT, JSON.stringify(output, null, 2), "utf8");
  console.log(
    `[build-docs] Written ${Object.keys(pages).length} pages to ${OUTPUT}`
  );
}

build();
