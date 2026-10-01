/* ==========================================================================
   analyser.js — the analysis engine
   --------------------------------------------------------------------------
   This file contains NO screen code. It turns raw pasted text into:
     * a context  (links, attachment names, e-mail headers)
     * a result   (score, band, findings, recommendations, stats)
   Keeping it separate means the logic can be read, reasoned about and tested
   on its own. Everything below runs locally in the browser.
   ========================================================================== */

(function () {
  'use strict';

  var PA = (window.PA = window.PA || {});

  /* Second-level labels used by multi-part public suffixes, so that
     'example.co.uk' is treated as one domain rather than 'co.uk'.       */
  var MULTI_LABEL_TLDS = [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz',
    'co.jp', 'co.in', 'net.in', 'com.br', 'com.mx', 'co.za', 'com.sg',
    'co.il', 'com.tr', 'com.hk', 'co.kr'
  ];

  /* --------------------------------------------------------- domain helpers --- */

  /* 'login.microsoft.com'  ->  'microsoft.com'   (the "real" site) */
  PA.registrable = function (host) {
    var parts = String(host || '').toLowerCase().split('.').filter(function (p) { return !!p; });
    if (parts.length <= 2) return parts.join('.');
    if (MULTI_LABEL_TLDS.indexOf(parts.slice(-2).join('.')) !== -1) return parts.slice(-3).join('.');
    return parts.slice(-2).join('.');
  };

  /* 'login.microsoft-verify.example' -> ['login','microsoft','verify','example']
     used to spot brand names hidden inside a domain                      */
  PA.tokensOf = function (host) {
    return String(host || '').toLowerCase()
      .split('.').join('-').split('_').join('-').split('-')
      .filter(function (t) { return !!t; });
  };

  /* 'Support <a@b.example>' -> 'b.example' */
  PA.domainOf = function (value) {
    var s = String(value || '').toLowerCase();
    var at = s.lastIndexOf('@');
    if (at === -1) return '';
    return s.slice(at + 1).replace(/[>,; ]+$/, '');
  };

  function isIPv4(host) {
    var h = String(host || '');
    if (!/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(h)) return false;
    var parts = h.split('.');
    for (var i = 0; i < parts.length; i++) {
      if (parseInt(parts[i], 10) > 255) return false;
    }
    return true;
  }

  /* Does this host pretend to be a brand it is not? */
  PA.detectLookalike = function (host) {
    var h = String(host || '').toLowerCase();
    var reg = PA.registrable(h);
    var s;
    for (s = 0; s < PA.LOOKALIKE_SWAPS.length; s++) {
      if (h.indexOf(PA.LOOKALIKE_SWAPS[s].fake) !== -1) {
        return 'imitates ' + PA.LOOKALIKE_SWAPS[s].real;
      }
    }
    var tokens = PA.tokensOf(h);
    for (var b = 0; b < PA.BRANDS.length; b++) {
      var brand = PA.BRANDS[b];
      for (var k = 0; k < brand.keys.length; k++) {
        var key = brand.keys[k];
        if (key.indexOf(' ') !== -1) continue;
        if (tokens.indexOf(key) === -1) continue;
        if (brand.domains.indexOf(reg) === -1) return 'imitates ' + brand.name;
      }
    }
    return null;
  };

  /* -------------------------------------------------------- link helpers --- */

  var DOMAIN_IN_TEXT = /[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*\.[a-z]{2,}/i;

  function domainFromText(text) {
    var m = DOMAIN_IN_TEXT.exec(String(text || '').toLowerCase());
    return m ? m[0] : '';
  }

  /* Does the visible text of a link disagree with where it actually goes? */
  PA.detectMismatch = function (text, host) {
    var t = String(text || '').toLowerCase().trim();
    if (!t) return false;
    var hostReg = PA.registrable(host);

    var um = /:\/\/([^\/?# ]+)/.exec(t);
    if (um && PA.registrable(um[1]) !== hostReg) return true;

    var cand = domainFromText(t);
    if (cand && PA.registrable(cand) !== hostReg) return true;

    for (var b = 0; b < PA.BRANDS.length; b++) {
      var brand = PA.BRANDS[b];
      for (var k = 0; k < brand.keys.length; k++) {
        var key = brand.keys[k];
        if (key.indexOf(' ') !== -1) continue;
        if (!new RegExp('(?:^|[^a-z0-9])' + key + '(?:[^a-z0-9]|$)').test(t)) continue;
        if (brand.domains.indexOf(hostReg) === -1) return true;
      }
    }
    return false;
  };

  var RE_HTML  = /<a\b[^>]*?href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;
  var RE_MD    = /\[([^\]\n]{1,200})\]\(\s*(https?:\/\/[^)\s]+)\s*\)/gi;
  var RE_PAREN = /([A-Za-z0-9][A-Za-z0-9._-]{2,80})\s*\(\s*(https?:\/\/[^)\s]+)\s*\)/g;
  var RE_BARE  = /https?:\/\/[^\s<>"')\]]+/gi;
  var RE_TAGS  = /<[^>]*>/g;
  var RE_URL   = /^([a-z][a-z0-9+.-]*):\/\/([^\/?#]+)([^#]*)/i;

  function parseUrl(href) {
    var h = String(href || '').trim().replace(/[.,;!?]+$/, '');
    var m = RE_URL.exec(h);
    if (!m) return null;
    var authority = m[2];
    var at = authority.lastIndexOf('@');           /* strip any user:pass@ */
    if (at !== -1) authority = authority.slice(at + 1);
    if (authority.indexOf(']') === -1) {           /* strip :port (keep IPv6) */
      var colon = authority.lastIndexOf(':');
      if (colon !== -1) authority = authority.slice(0, colon);
    }
    return { href: h, scheme: m[1].toLowerCase(), host: authority.toLowerCase(), path: m[3] || '' };
  }

  /* Pull every link out of the text, without ever visiting one. */
  PA.extractLinks = function (raw) {
    var text = String(raw || '');
    var list = [];
    var seen = {};

    function push(href, display, explicit) {
      var p = parseUrl(href);
      if (!p || !p.host) return;
      var key = p.href.toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      var link = {
        href: p.href,
        host: p.host,
        scheme: p.scheme,
        text: explicit && display ? String(display).trim() : p.href,
        explicit: !!explicit
      };
      link.ip = isIPv4(p.host) || p.host.charAt(0) === '[';
      link.punycode = p.host.indexOf('xn--') !== -1 || /[^\x20-\x7e]/.test(p.host);
      link.shortener = PA.SHORTENERS.indexOf(PA.registrable(p.host)) !== -1 ||
                       PA.SHORTENERS.indexOf(p.host) !== -1;
      link.lookalike = PA.detectLookalike(p.host);
      link.mismatch = explicit ? PA.detectMismatch(String(display || ''), p.host) : false;
      list.push(link);
    }

    function run(re) {
      re.lastIndex = 0;
      var m;
      var guard = 0;
      while ((m = re.exec(text)) !== null && guard++ < 200) {
        push(m[2], m[1], true);
        if (list.length > 80) break;
      }
    }

    function runHtml() {
      RE_HTML.lastIndex = 0;
      var m;
      var guard = 0;
      while ((m = RE_HTML.exec(text)) !== null && guard++ < 200) {
        push(m[1], m[2].replace(RE_TAGS, ' ').replace(/\s+/g, ' ').trim(), true);
        if (list.length > 80) break;
      }
    }

    function runBare() {
      RE_BARE.lastIndex = 0;
      var m;
      var guard = 0;
      while ((m = RE_BARE.exec(text)) !== null && guard++ < 400) {
        push(m[0], m[0], false);
        if (list.length > 80) break;
      }
    }

    runHtml();
    run(RE_MD);
    run(RE_PAREN);
    runBare();
    return list;
  };

  /* ------------------------------------------------------- attachment names --- */

  var INTERESTING_EXT = (function () {
    var all = PA.DANGEROUS_EXT.concat(PA.MACRO_EXT).concat(PA.ARCHIVE_EXT)
      .concat(PA.LEGACY_OFFICE_EXT)
      .concat(['pdf', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'jpg', 'jpeg', 'png', 'gif',
               'bmp', 'svg', 'txt', 'csv', 'rtf', 'html', 'htm', 'eml', 'msg', 'iso']);
    var map = {};
    for (var i = 0; i < all.length; i++) map[all[i]] = true;
    return map;
  })();

  /* Extensions that are really internet domain endings rather than file
     types. '.com' is technically a legacy program file, but in an email body
     'something.com' is almost always a web address, so we ignore it here.   */
  var TLD_LIKE = {};
  var TLD_LIST = [
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'io', 'co', 'uk',
    'us', 'ca', 'de', 'fr', 'au', 'jp', 'cn', 'ru', 'nl', 'se', 'no', 'es', 'it', 'ch',
    'be', 'at', 'dk', 'fi', 'pl', 'br', 'in', 'mx', 'za', 'nz', 'ie', 'pt', 'gr', 'cz',
    'kr', 'sg', 'hk', 'tw', 'th', 'my', 'id', 'ph', 'vn', 'ae', 'sa', 'il', 'tr', 'test',
    'example', 'invalid', 'localhost', 'dev', 'app', 'xyz', 'online', 'site', 'cloud',
    'live', 'me', 'tv', 'cc', 'ai', 'shop', 'store', 'tech', 'email', 'name', 'pro',
    'mobi', 'asia', 'one', 'top', 'link', 'click', 'work', 'space', 'agency', 'company'
  ];
  for (var tl = 0; tl < TLD_LIST.length; tl++) { TLD_LIKE[TLD_LIST[tl]] = true; }

  var RE_FILENAME = /\b([A-Za-z0-9][A-Za-z0-9 ._-]{0,60}\.[A-Za-z0-9]{1,8})\b/g;

  PA.extractAttachments = function (raw) {
    var text = String(raw || '');
    var found = [];
    RE_FILENAME.lastIndex = 0;
    var m;
    var guard = 0;
    while ((m = RE_FILENAME.exec(text)) !== null && guard++ < 400) {
      var name = m[1].trim();
      if (name.indexOf('@') !== -1) continue;
      var ext = PA.extOf(name);
      if (!ext || !INTERESTING_EXT[ext]) continue;
      if (TLD_LIKE[ext]) continue;
      if (found.indexOf(name) === -1) found.push(name);
      if (found.length > 20) break;
    }
    return found;
  };


  /* -------------------------------------------------------- e-mail headers --- */

  var RE_HEADER  = /^([A-Za-z][A-Za-z0-9-]*)[ ]*:(.*)$/;
  var RE_EMAIL   = /[^ <>@,;"']+@[^ <>@,;"']+/;
  var HEADER_NAMES = ['from', 'reply-to', 'return-path', 'received-spf',
                      'authentication-results', 'received', 'dkim-signature',
                      'message-id', 'date', 'subject', 'to'];

  PA.parseHeaders = function (raw) {
    var out = {
      present: false, from: null, replyTo: null,
      spf: null, dkim: null, dmarc: null, authRaw: ''
    };
    var text = String(raw || '');
    var CR = String.fromCharCode(13), LF = String.fromCharCode(10), TAB = String.fromCharCode(9);

    /* join folded header lines (they start with a space or a tab) */
    var rawLines = text.split(CR).join(LF).split(LF);
    var lines = [];
    for (var i = 0; i < rawLines.length; i++) {
      var line = rawLines[i];
      if (lines.length && (line.charAt(0) === ' ' || line.charAt(0) === TAB)) {
        lines[lines.length - 1] += ' ' + line.trim();
      } else {
        lines.push(line);
      }
    }

    var auth = [];
    for (var j = 0; j < lines.length; j++) {
      var hm = RE_HEADER.exec(lines[j]);
      if (!hm) continue;
      var name = hm[1].toLowerCase();
      var value = hm[2].trim();
      if (HEADER_NAMES.indexOf(name) === -1) continue;
      out.present = true;

      if (name === 'from' && !out.from) {
        var fm = RE_EMAIL.exec(value);
        if (fm) out.from = fm[0].toLowerCase();
      } else if (name === 'reply-to' && !out.replyTo) {
        var rm = RE_EMAIL.exec(value);
        if (rm) out.replyTo = rm[0].toLowerCase();
      } else if (name === 'received-spf' && !out.spf) {
        var sm = /^(pass|fail|softfail|neutral|none|permerror|temperror)/i.exec(value);
        out.spf = sm ? sm[1].toLowerCase() : null;
      } else if (name === 'authentication-results') {
        auth.push(value);
      }
    }

    out.authRaw = auth.join('  ');
    var am;
    if (!out.spf) { am = /spf[ ]*=[ ]*([a-z0-9]+)/i.exec(out.authRaw); if (am) out.spf = am[1].toLowerCase(); }
    am = /dkim[ ]*=[ ]*([a-z0-9]+)/i.exec(out.authRaw); if (am) out.dkim = am[1].toLowerCase();
    am = /dmarc[ ]*=[ ]*([a-z0-9]+)/i.exec(out.authRaw); if (am) out.dmarc = am[1].toLowerCase();
    return out;
  };

  /* ------------------------------------------------------------- the result --- */

  function unique(values) {
    var out = [];
    for (var i = 0; i < values.length; i++) {
      if (out.indexOf(values[i]) === -1) out.push(values[i]);
    }
    return out;
  }

  PA.buildContext = function (raw) {
    var text = String(raw == null ? '' : raw);
    return {
      raw: text,
      text: text.toLowerCase(),
      links: PA.extractLinks(text),
      attachments: PA.extractAttachments(text),
      headers: PA.parseHeaders(text)
    };
  };

  /* The main entry point: text in, explainable result out. */
  PA.analyse = function (raw) {
    var ctx = PA.buildContext(raw);
    var findings = [];

    for (var i = 0; i < PA.RULES.length; i++) {
      var r = PA.RULES[i];
      var evidence = [];
      try {
        evidence = r.detect(ctx) || [];
      } catch (err) {
        evidence = [];
      }
      var clean = [];
      for (var e = 0; e < evidence.length; e++) {
        var v = String(evidence[e] == null ? '' : evidence[e]).replace(/\s+/g, ' ').trim();
        if (v.length > 90) v = v.slice(0, 87) + '...';
        if (v && clean.indexOf(v) === -1) clean.push(v);
        if (clean.length >= 5) break;
      }
      clean.sort(function (x, y) { return x.length - y.length; });
      if (clean.length) {
        findings.push({
          id: r.id, title: r.title, weight: r.weight, severity: r.severity,
          category: r.category, why: r.why, evidence: clean
        });
      }
    }

    findings.sort(function (a, b) { return b.weight - a.weight; });

    var rawScore = 0;
    for (var f = 0; f < findings.length; f++) rawScore += findings[f].weight;
    var score = Math.min(PA.MAX_SCORE, rawScore);

    var subjectM = /^[ ]*subject[ ]*:[ ]*(.+)$/im.exec(ctx.raw);
    var trimmed = ctx.raw.trim();

    return {
      score: score,
      rawScore: rawScore,
      capped: rawScore > PA.MAX_SCORE,
      band: PA.bandForScore(score),
      findings: findings,
      recommendations: PA.buildRecommendations(findings),
      stats: {
        subject: subjectM ? subjectM[1].trim() : '',
        characters: ctx.raw.length,
        words: trimmed ? trimmed.split(/\s+/).length : 0,
        linkCount: ctx.links.length,
        hosts: unique(ctx.links.map(function (l) { return l.host; })),
        attachmentCount: ctx.attachments.length,
        attachments: ctx.attachments,
        headers: ctx.headers
      }
    };
  };
})();

