// Copy this file to Mypal's profile folder as USER.JS (C:\WINDOWS\DESKTOP\MYPAL\PROFILE\USER.JS for the
// portable Mypal; Mypal reads it at every start). Delete USER.JS again to undo (the settings stay in PREFS.JS
// until you change them back in about:config).
// KernelEx-NG settings for Windows 98 and slow PCs (2026-11-02). Each line: what it saves.

// No hardware acceleration: Direct3D 9 / ANGLE on Windows 98 only adds work and crashes.
user_pref("layers.acceleration.disabled", true);
user_pref("webgl.disabled", true);
user_pref("gfx.direct2d.disabled", true);
user_pref("media.hardware-video-decoding.enabled", false);
user_pref("gfx.content.azure.backends", "skia");
user_pref("gfx.canvas.azure.backends", "skia");

// Scrolling and animation: draw fewer frames.
user_pref("general.smoothScroll", false);          // one repaint per scroll step instead of ~10
user_pref("layout.frame_rate", 30);                // at most 30 repaints a second (default: 60)
user_pref("browser.tabs.animate", false);
user_pref("browser.fullscreen.animate", false);

// Page loading: lay the page out fewer times while it streams in.
user_pref("content.notify.ontimer", true);
user_pref("content.notify.interval", 500000);      // re-layout at most every 0.5 s while loading
user_pref("nglayout.initialpaint.delay", 500);

// Less background work and memory.
user_pref("browser.sessionhistory.max_total_viewers", 0);   // don't keep whole old pages in memory for Back
user_pref("browser.sessionstore.interval", 60000);          // save the session every 60 s (default 15 s)
user_pref("browser.cache.memory.capacity", 32768);          // 32 MB memory cache
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.http.speculative-parallel-limit", 0);
