import { describe, expect, it } from "vitest";
import { addressRefusal, addresses, assertProbe, hostName, inCidr, isForbidden, isPrivate, parseCidr, rootOf, type Roots } from "./scope.ts";

const roots = (over: Partial<Roots> = {}): Roots => ({ domains: ["example.com"], ranges: [parseCidr("203.0.113.0/28")], allowPrivate: false, ...over });

describe("host names", () => {
  it("are lower case without the trailing dot, and must be names", () => {
    expect(hostName("WWW.Example.COM.")).toBe("www.example.com");
    for (const bad of ["com", "203.0.113.5", "-a.example.com", "a..example.com", "a b.example.com", "example.123", "*.example.com", ""])
      expect(hostName(bad)).toBeNull();
  });

  it("belong to the longest verified domain they are under, and never to a look-alike", () => {
    expect(rootOf("api.shop.example.com", ["example.com", "shop.example.com"])).toBe("shop.example.com");
    expect(rootOf("example.com", ["example.com"])).toBe("example.com");
    expect(rootOf("badexample.com", ["example.com"])).toBeNull();
    expect(rootOf("example.com.evil.net", ["example.com"])).toBeNull();
  });
});

describe("addresses", () => {
  it("never probes loopback, link-local, multicast or unspecified ones", () => {
    for (const a of ["127.0.0.1", "0.0.0.0", "169.254.169.254", "224.0.0.1", "::1", "::", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "[::1]", "nonsense"])
      expect(isForbidden(a), a).toBe(true);
    expect(isForbidden("203.0.113.5")).toBe(false);
    expect(isForbidden("2001:db8::1")).toBe(false);
  });

  it("knows private ones, and refuses them unless the install allows it", () => {
    for (const a of ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fd00::1", "::ffff:10.0.0.1"]) expect(isPrivate(a), a).toBe(true);
    for (const a of ["172.32.0.1", "8.8.8.8", "2001:db8::1"]) expect(isPrivate(a), a).toBe(false);
    expect(addressRefusal("10.0.0.5", roots())).toMatch(/private/);
    expect(addressRefusal("10.0.0.5", roots({ allowPrivate: true }))).toBeNull();
    expect(addressRefusal("169.254.169.254", roots({ allowPrivate: true }))).toMatch(/never/);
  });
});

describe("ranges", () => {
  it("are read as CIDR with no host bits, at most 256 addresses", () => {
    expect(parseCidr(" 203.0.113.16/28 ")).toMatchObject({ cidr: "203.0.113.16/28", family: 4, size: 16n });
    expect(parseCidr("198.51.100.7").cidr).toBe("198.51.100.7/32");
    expect(parseCidr("2001:DB8:0:0::/124").cidr).toBe("2001:db8::/124");
    expect(() => parseCidr("203.0.113.5/28")).toThrow(/starts at 203.0.113.0\/28/);
    expect(() => parseCidr("203.0.112.0/23")).toThrow(/at most 256/);
    expect(() => parseCidr("2001:db8::/64")).toThrow(/at most 256/);
    for (const bad of ["203.0.113.0/33", "203.0.113.0/x", "example.com/24", "1.2.3.4/24/1", "203.0.113.0/"]) expect(() => parseCidr(bad), bad).toThrow();
  });

  it("hold the addresses they say", () => {
    const r = parseCidr("203.0.113.252/30");
    expect(addresses(r)).toEqual(["203.0.113.252", "203.0.113.253", "203.0.113.254", "203.0.113.255"]);
    expect(inCidr("203.0.113.255", r)).toBe(true);
    expect(inCidr("203.0.114.0", r)).toBe(false);
    expect(inCidr("2001:db8::1", r)).toBe(false);
    expect(addresses(parseCidr("2001:db8::fe/127"))).toEqual(["2001:db8::fe", "2001:db8::ff"]);
  });
});

describe("assertProbe", () => {
  it("lets a name under a verified domain be probed at a public address", () => {
    expect(() => assertProbe({ name: "api.example.com", address: "198.51.100.9" }, roots())).not.toThrow();
  });

  it("refuses a name outside the verified domains, wherever it points", () => {
    expect(() => assertProbe({ name: "example.net", address: "203.0.113.1" }, roots())).toThrow(/not under a verified domain/);
    expect(() => assertProbe({ name: "notexample.com", address: "198.51.100.9" }, roots())).toThrow(/not under a verified domain/);
    expect(() => assertProbe({ name: "api.example.com", address: "198.51.100.9" }, roots({ domains: [] }))).toThrow(/not under a verified domain/);
  });

  it("lets an address be probed alone only inside a range an admin added", () => {
    expect(() => assertProbe({ name: null, address: "203.0.113.15" }, roots())).not.toThrow();
    expect(() => assertProbe({ name: null, address: "203.0.113.16" }, roots())).toThrow(/not in a range/);
  });

  it("refuses forbidden and private addresses even for verified names", () => {
    expect(() => assertProbe({ name: "www.example.com", address: "127.0.0.1" }, roots())).toThrow(/never probed/);
    expect(() => assertProbe({ name: "www.example.com", address: "10.0.0.1" }, roots())).toThrow(/private/);
  });
});
