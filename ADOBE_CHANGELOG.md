# About

We maintain a set of patches on top of upstream fluent-bit. They need to be
semantically versioned as well so we understand, for example, that we're
upgrading a fix version of fluent-bit vs. a fix version of our patches.

The scheme is quite simple. The upstream version is first, followed by a hyphen,
followed by our version:

```
F stands for Fluent-Bit
A stands for Adobe's changes

{F major}.{F minor}.{F fix}-{A major}.{A minor}.{A fix}-adobe
```

# Log

## 1.5.6-0.5.0-adobe

- configurable http buffer size (default unlimited)
- changed user default envoy filter to `not2xx`

## 1.5.6-0.4.0-adobe

- configurable cache ttl
- fix issue with option `Filter` being ignored

## 1.5.6-0.3.0-adobe

- built from v1.5.6

## 1.5.4-0.3.0-adobe

- added support for event and audit logs
- added new http filter `not2xx`
- renamed option `Envoy_Filter` to `Filter`

## 1.5.4-0.2.0-adobe

- built from v1.5.4

## 1.5.3-0.2.0-adobe

- caching / re-emitting fixes
- use config map for configuration values
- filter log by http code
- run fluent-bit under proces supervision (s6)
- various fixes and code cleanup

## 1.5.3-0.1.0-adobe

- built from v1.5.3
- various fixups

## 1.5.2-0.0.5-adobe

- built from v1.5.2

## 1.4.6-0.0.5-adobe

- built from v1.4.6

## 1.4.5-0.0.5-adobe

- platform_log
