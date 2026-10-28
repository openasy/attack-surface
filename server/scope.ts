// What Attack Surface may touch (ADR 0067). A name is in scope when it is a verified domain or a name under one; an
// address is in scope when it is in a range an admin added. Nothing else is ever connected to: names found outside
// the roots are listed, and left alone. Every connection the scanner makes passes through assertProbe() first.
import { isIP } from "node:net";

/** Addresses that are never probed, whatever the roots say: this host, link-local (cloud metadata), multicast, unspecified. */
export function isForbidden(address: string): boolean {
  const a = normalize(address);
  if (a.startsWith("::ffff:") && isIP(a.slice(7)) === 4) return isForbidden(a.slice(7));
  if (isIP(a) === 4) {
    const [p, q] = a.split(".").map(Number) as [number, number];
    return p === 0 || p === 127 || (p === 169 && q === 254) || p >= 224;
  }
  if (isIP(a) === 6) {
    const h = expand6(a);
    return h === "0".repeat(32) || h === "0".repeat(31) + "1" || /^fe[89ab]/.test(h) || h.startsWith("ff");
  }
  return true;
}

/** Private and shared addresses: reachable only inside a network, so not part of what the internet sees. */
export function isPrivate(address: string): boolean {
  const a = normalize(address);
  if (a.startsWith("::ffff:") && isIP(a.slice(7)) === 4) return isPrivate(a.slice(7));
  if (isIP(a) === 4) {
    const [p, q] = a.split(".").map(Number) as [number, number];
    return (
      p === 10 || (p === 100 && q >= 64 && q <= 127) || (p === 172 && q >= 16 && q <= 31) || (p === 192 && q === 168) || (p === 198 && (q === 18 || q === 19))
    );
  }
  if (isIP(a) === 6) return /^f[cd]/.test(expand6(a));
  return false;
}

const normalize = (address: string) => address.toLowerCase().replace(/^\[|\]$/g, "");

/** An IPv6 address as 32 hex digits. */
function expand6(address: string): string {
  let a = address;
  // An IPv4 tail, as in ::ffff:192.0.2.1, becomes two groups.
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (v4) {
    const n = v4[1]!.split(".").map(Number);
    a = a.slice(0, -v4[1]!.length) + `${((n[0]! << 8) | n[1]!).toString(16)}:${((n[2]! << 8) | n[3]!).toString(16)}`;
  }
  const [head, tail] = a.includes("::") ? a.split("::") : [a, undefined];
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = tail === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  return groups.map((g) => g.padStart(4, "0")).join("");
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/** A host name as DNS has it: lower case, no trailing dot. Returns null for anything that is not one. */
export function hostName(raw: string): string | null {
  const name = raw.trim().toLowerCase().replace(/\.$/, "");
  if (name.length > 253 || isIP(name)) return null;
  const labels = name.split(".");
  return labels.length >= 2 && labels.every((l) => LABEL.test(l)) && !/^\d+$/.test(labels.at(-1)!) ? name : null;
}

/** Whether name is the domain or a name under it. Both are host names as hostName() returns them. */
export const inDomain = (name: string, domain: string) => name === domain || name.endsWith(`.${domain}`);

/** The verified domain a name belongs to, the longest that matches, or null when it is outside every one. */
export function rootOf(name: string, domains: readonly string[]): string | null {
  let best: string | null = null;
  for (const d of domains) if (inDomain(name, d) && (!best || d.length > best.length)) best = d;
  return best;
}

export interface Cidr {
  /** The network as written back: the first address and the prefix, such as 203.0.113.0/28. */
  cidr: string;
  family: 4 | 6;
  first: bigint;
  size: bigint;
}

/** The most addresses one range may hold: a /24 or a /120. A scan of more is a scan of somebody's network, not a few hosts. */
export const MAX_RANGE = 256n;

function toBig(address: string): { family: 4 | 6; value: bigint } | null {
  const a = normalize(address);
  if (isIP(a) === 4) return { family: 4, value: a.split(".").reduce((n, o) => (n << 8n) | BigInt(o), 0n) };
  if (isIP(a) === 6) return { family: 6, value: BigInt(`0x${expand6(a)}`) };
  return null;
}

export function fromBig(family: 4 | 6, value: bigint): string {
  if (family === 4) return [24n, 16n, 8n, 0n].map((s) => String((value >> s) & 255n)).join(".");
  const hex = value.toString(16).padStart(32, "0");
  const groups = hex.match(/.{4}/g)!.map((g) => g.replace(/^0+(?=.)/, ""));
  // The longest run of zero groups becomes ::, as addresses are usually written.
  let start = -1;
  let len = 0;
  for (let i = 0; i < 8; i++) {
    let j = i;
    while (j < 8 && groups[j] === "0") j++;
    if (j - i > len && j - i > 1) [start, len] = [i, j - i];
  }
  if (start < 0) return groups.join(":");
  return `${groups.slice(0, start).join(":")}::${groups.slice(start + len).join(":")}`;
}

/** Reads an address or a range in CIDR notation. Host bits must be zero, so what is written is what is scanned. */
export function parseCidr(raw: string): Cidr {
  const [address = "", prefixText, ...rest] = raw.trim().split("/");
  const ip = toBig(address);
  if (!ip || rest.length) throw new Error("Write an address or a range in CIDR notation, such as 203.0.113.0/28 or 2001:db8::/124.");
  const bits = ip.family === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? bits : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits || (prefixText !== undefined && !/^\d+$/.test(prefixText)))
    throw new Error(`The prefix of an IPv${ip.family} range is 0 to ${bits}.`);
  const size = 1n << BigInt(bits - prefix);
  if (ip.value % size !== 0n)
    throw new Error(`${raw.trim()} has host bits set; the range starts at ${fromBig(ip.family, ip.value - (ip.value % size))}/${prefix}.`);
  if (size > MAX_RANGE)
    throw new Error(`A range holds at most ${MAX_RANGE} addresses, a /${ip.family === 4 ? 24 : 120}; add larger networks as several ranges.`);
  return { cidr: `${fromBig(ip.family, ip.value)}/${prefix}`, family: ip.family, first: ip.value, size };
}

export function inCidr(address: string, range: Cidr): boolean {
  const ip = toBig(address);
  return !!ip && ip.family === range.family && ip.value >= range.first && ip.value < range.first + range.size;
}

/** Every address of a range, in order. */
export function addresses(range: Cidr): string[] {
  const out: string[] = [];
  for (let i = 0n; i < range.size; i++) out.push(fromBig(range.family, range.first + i));
  return out;
}

export interface Roots {
  /** Verified domains only. A domain that is pending or whose record has gone is not here. */
  domains: readonly string[];
  ranges: readonly Cidr[];
  /** Private addresses may be probed (ATTACK_SURFACE_ALLOW_PRIVATE, for labs). Forbidden ones never are. */
  allowPrivate: boolean;
  /** Only tests set it, to reach their servers on 127.0.0.1; there is no setting for it. */
  allowLoopback?: boolean;
}

/** Why an address is not probed, or null when it may be. */
export function addressRefusal(address: string, roots: Roots): string | null {
  if (roots.allowLoopback && toBig(address)?.family === 4 && address.startsWith("127.")) return null;
  if (isForbidden(address)) return "a loopback, link-local or multicast address, never probed";
  if (isPrivate(address) && !roots.allowPrivate) return "a private address, not reachable from the internet; not probed";
  return null;
}

export class OutOfScope extends Error {}

/**
 * The last check before any connection. A probe goes to an address as a name: the name must be under a verified
 * domain, or, with no name, the address must be in a range an admin added. The address must also not be refused.
 */
export function assertProbe(target: { name: string | null; address: string }, roots: Roots): void {
  const refusal = addressRefusal(target.address, roots);
  if (refusal) throw new OutOfScope(`${target.address} is ${refusal}.`);
  if (target.name !== null) {
    const name = hostName(target.name);
    if (!name || !rootOf(name, roots.domains)) throw new OutOfScope(`${target.name} is not under a verified domain.`);
    return;
  }
  if (!roots.ranges.some((r) => inCidr(target.address, r))) throw new OutOfScope(`${target.address} is not in a range an admin added.`);
}
