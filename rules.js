/* ==========================================================================
   rules.js — the knowledge base of the analyser
   --------------------------------------------------------------------------
   Everything the analyser knows lives here:
     * PA.BANDS       — how a 0–100 score maps to Low / Suspicious / High Risk
     * PA.BRANDS      — well-known brands and their official domains (for
                        look-alike detection)
     * PA.SHORTENERS  — link-shortening services
     * PA.DANGEROUS_EXT / PA.MACRO_EXT — risky attachment file types
     * PA.RULES       — every indicator, its fixed point value, the plain-English
                        explanation and the detection function
     * PA.DEMOS       — the fictional demo emails

   WHERE TO CHANGE THINGS (you cannot break the tool by editing numbers):
     Want an indicator to matter more or less?  Change its `weight` below.
     Want to add a phrase the tool looks for?  Add it to the rule's patterns.

   Each rule's `detect(context)` returns an ARRAY of evidence strings.
   An empty array means "this warning sign was not found".
   ========================================================================== */

(function () {
  'use strict';

  var PA = (window.PA = window.PA || {});

  /* ------------------------------------------------------------- scoring --- */

  PA.BANDS = [
    { id: 'low', label: 'Low Risk', max: 24,
      summary: 'Few or no warning signs were found. This does not prove the email is safe.' },
    { id: 'suspicious', label: 'Suspicious', max: 59,
      summary: 'Several warning signs were found. Treat this message with caution and verify it.' },
    { id: 'high', label: 'High Risk', max: 100,
      summary: 'Strong warning signs of phishing were found. Do not act on this message.' }
  ];

  PA.MAX_SCORE = 100;

  PA.bandForScore = function (score) {
    for (var i = 0; i < PA.BANDS.length; i++) {
      if (score <= PA.BANDS[i].max) return PA.BANDS[i];
    }
    return PA.BANDS[PA.BANDS.length - 1];
  };

  /* --------------------------------------------------------------- brands --- */
  /* Used to spot domains that pretend to be a trusted brand.
     `lookalikes` catches the classic digit/letter swaps used in fakes.        */

  PA.BRANDS = [
    { name: 'Microsoft', keys: ['microsoft', 'office 365', 'office365', 'outlook', 'onedrive', 'sharepoint'],
      domains: ['microsoft.com', 'office.com', 'microsoftonline.com', 'sharepoint.com', 'live.com', 'outlook.com', 'windows.net', 'azure.com'] },
    { name: 'Apple', keys: ['apple', 'icloud'],
      domains: ['apple.com', 'icloud.com', 'me.com'] },
    { name: 'Google', keys: ['google', 'gmail', 'googlemail'],
      domains: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com'] },
    { name: 'Amazon', keys: ['amazon', 'aws'],
      domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca'] },
    { name: 'PayPal', keys: ['paypal'],
      domains: ['paypal.com', 'paypal.co.uk', 'paypal.me'] },
    { name: 'Netflix', keys: ['netflix'], domains: ['netflix.com'] },
    { name: 'DHL', keys: ['dhl'], domains: ['dhl.com', 'dhl.de', 'dhl.co.uk'] },
    { name: 'FedEx', keys: ['fedex'], domains: ['fedex.com'] },
    { name: 'UPS', keys: ['ups'], domains: ['ups.com'] },
    { name: 'Royal Mail', keys: ['royalmail', 'royal mail'], domains: ['royalmail.com', 'royalmailgroup.com'] },
    { name: 'HMRC', keys: ['hmrc'], domains: ['gov.uk', 'hmrc.gov.uk'] },
    { name: 'DocuSign', keys: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'Dropbox', keys: ['dropbox'], domains: ['dropbox.com'] },
    { name: 'Adobe', keys: ['adobe'], domains: ['adobe.com'] },
    { name: 'LinkedIn', keys: ['linkedin'], domains: ['linkedin.com'] },
    { name: 'Facebook', keys: ['facebook', 'meta'], domains: ['facebook.com', 'fb.com', 'meta.com'] },
    { name: 'Instagram', keys: ['instagram'], domains: ['instagram.com'] },
    { name: 'WhatsApp', keys: ['whatsapp'], domains: ['whatsapp.com', 'wa.me'] },
    { name: 'X / Twitter', keys: ['twitter'], domains: ['twitter.com', 'x.com'] },
    { name: 'Spotify', keys: ['spotify'], domains: ['spotify.com'] },
    { name: 'Steam', keys: ['steam'], domains: ['steampowered.com', 'steamcommunity.com'] }
  ];

  /* Digit-for-letter disguises, e.g. paypa1.com, micros0ft.com */
  PA.LOOKALIKE_SWAPS = [
    { fake: 'paypa1', real: 'PayPal' }, { fake: 'micros0ft', real: 'Microsoft' },
    { fake: 'microsft', real: 'Microsoft' }, { fake: 'mlcrosoft', real: 'Microsoft' },
    { fake: 'g00gle', real: 'Google' }, { fake: 'arnazon', real: 'Amazon' },
    { fake: 'amaz0n', real: 'Amazon' }, { fake: 'app1e', real: 'Apple' },
    { fake: 'netfl1x', real: 'Netflix' }, { fake: 'faceb00k', real: 'Facebook' },
    { fake: '1inkedin', real: 'LinkedIn' }, { fake: 'rnicrosoft', real: 'Microsoft' },
    { fake: 'docuslgn', real: 'DocuSign' }, { fake: 'royalmaill', real: 'Royal Mail' }
  ];

  /* ------------------------------------------------------------ link data --- */

  PA.SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in', 's.id', 'qrco.de', 'bit.do',
    'mcaf.ee', 'budurl.com', 'snipurl.com', 'clck.ru', 'v.gd', 'x.co', 'tr.im', 'urlz.fr',
    'trib.al', 't.ly', 'shorte.st', 'adf.ly', 'u.to', 'gg.gg', 'short.gy'
  ];

  PA.DANGEROUS_EXT = [
    'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh',
    'ps1', 'psm1', 'hta', 'lnk', 'msi', 'msp', 'jar', 'reg', 'dll', 'cpl', 'msc', 'inf',
    'job', 'gadget', 'apk', 'iso', 'img', 'vhd', 'diagcab', 'scf', 'url'
  ];

  PA.MACRO_EXT = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'xlam', 'potm', 'ppam', 'sldm'];
  PA.LEGACY_OFFICE_EXT = ['doc', 'xls', 'ppt', 'dot', 'xlt'];
  PA.ARCHIVE_EXT = ['zip', 'rar', '7z', 'gz', 'tar', 'tgz', 'cab', 'ace', 'bz2'];

  /* -------------------------------------------------------- small helpers --- */

  /* Run a case-insensitive global search and collect up to `limit` matched
     strings (using capture group 1 when the pattern defines one).          */
  PA.scan = function (text, pattern, limit) {
    var out = [];
    var re;
    try { re = new RegExp(pattern, 'gi'); } catch (e) { return out; }
    var m;
    var guard = 0;
    while ((m = re.exec(text)) !== null && guard++ < 4000) {
      var val = (m[1] || m[0] || '').replace(/\s+/g, ' ').trim();
      if (val && out.indexOf(val) === -1) out.push(val);
      if (out.length >= (limit || 6)) break;
      if (m.index === re.lastIndex) re.lastIndex++;
    }
    return out;
  };

  PA.contains = function (text, pattern) {
    try { return new RegExp(pattern, 'i').test(text); } catch (e) { return false; }
  };

  /* ---------------------------------------------------------------- rules --- */
  /* NOTE: `detect(ctx)` receives the analysed context and returns evidence.
     ctx.text        — the whole email, lower-cased
     ctx.raw         — the original text as pasted
     ctx.links       — array of { href, host, text, ok } parsed from the email
     ctx.attachments — array of file names found in the text
     ctx.headers     — { from, replyTo, spf, dkim, dmarc, present }
  */

  PA.RULES = [];

  function rule(def) { PA.RULES.push(def); }

  /* ============================ credential theft ============================ */

  rule({
    id: 'password_request',
    title: 'Asks for your password',
    weight: 25,
    severity: 'high',
    category: 'Credential theft',
    why: "No legitimate organisation asks you to reply with, type out or 'confirm' your password in an email. Passwords should only ever be typed into a site you navigated to yourself.",
    detect: function (ctx) {
      var a = PA.scan(ctx.text, "(?:reply|respond|send|provide|confirm|enter|type|update|verify|supply|share|re-?enter|submit|give|tell us|let us know)[^.]{0,30}?\\b(?:password|passphrase|pwd)\\b", 4);
      var b = PA.scan(ctx.text, "\\b(?:password|passphrase|pwd)\\b[^.]{0,30}?(?:reply|respond|send|provide|confirm|enter|type|update|verify|supply|share|submit|is required|is needed|required)", 4);
      return a.concat(b);
    }
  });

  rule({
    id: 'mfa_code_request',
    title: 'Asks for an MFA / verification code',
    weight: 25,
    severity: 'high',
    category: 'Credential theft',
    why: 'Verification codes are the second lock on your account. Sharing a code, or typing one into a page you reached from a link, can let an attacker log in as you.',
    detect: function (ctx) {
      return PA.scan(ctx.text, "(?:one[-\\s]?time (?:password|code|passcode)|verification code|security code|authentication code|2fa code|two[-\\s]?factor code|mfa code|authenticator code|\\botp\\b|passcode|\\bcode (?:we|i) (?:just )?(?:sent|texted|emailed))", 4);
    }
  });

  rule({
    id: 'credential_harvesting',
    title: 'Credential-harvesting wording',
    weight: 12,
    severity: 'high',
    category: 'Credential theft',
    why: "Wording that pushes you to 'verify', 'confirm' or 're-activate' an account is designed to send you to a fake log-in page that captures whatever you type.",
    detect: function (ctx) {
      return PA.scan(ctx.text, "(?:verif(?:y|ication) your (?:account|identity|information|email|details|payment|billing|address|delivery)|confirm your (?:account|identity|information|email|details|billing|address|delivery|payment|card|bank)|validate your account|reactivate your account|re-?verif(?:y|ication)|restore your (?:account|access)|sign in to (?:continue|view|restore|verify)|log ?in to (?:continue|view|verify)|update your (?:account )?(?:information|details|billing|payment)|unlock your account|secure your account|account (?:has been|was) (?:compromised|suspended|locked|deactivated)|unusual (?:sign[- ]?in|login|activity)|unrecognis?ed (?:device|sign[- ]?in|login))", 5);
    }
  });

  /* ============================== fraud / money ============================= */

  rule({
    id: 'gift_card_payment',
    title: 'Requests payment by gift card or cryptocurrency',
    weight: 20,
    severity: 'high',
    category: 'Fraud & payment',
    why: 'Gift cards and cryptocurrency are effectively untraceable. Genuine organisations do not ask for payment this way — it is a classic sign of fraud and CEO-impersonation scams.',
    detect: function (ctx) {
      return PA.scan(ctx.text, "(?:gift ?cards?|itunes (?:card|voucher|gift)|google play (?:card|gift|voucher)|steam (?:card|wallet|gift)|prepaid card|wire transfer|moneygram|western union|money order|bitcoin|\\bbtc\\b|ethereum|\\busdt\\b|cryptocurrenc\\w*|crypto ?(?:wallet|payment|currency|transfer))", 4);
    }
  });

  rule({
    id: 'bank_detail_change',
    title: 'Asks you to change bank or payment details',
    weight: 20,
    severity: 'high',
    category: 'Fraud & payment',
    why: 'Requests to change bank details by email are a classic Business Email Compromise (BEC) trick used to divert a real payment into an attacker\'s account.',
    detect: function (ctx) {
      return PA.scan(ctx.text, "(?:update[d]? (?:our|my|your|the) ?(?:bank|payment|billing|beneficiary|wire|direct deposit|remittance|account) (?:details|information|account|number|instructions)|new (?:bank|beneficiary|account) (?:details|number|information|instructions)|change of bank (?:account|details)|revised (?:bank|payment|remittance|banking) details|updated (?:bank|payment|remittance) (?:details|information)|direct deposit (?:details|information|change)|(?:our|my) (?:bank|payment) details have changed)", 4);
    }
  });

  rule({
    id: 'unexpected_invoice',
    title: 'Unexpected invoice or payment demand',
    weight: 10,
    severity: 'medium',
    category: 'Fraud & payment',
    why: 'Unexpected invoices, statements and payment demands are used to trick people — especially finance teams — into paying a fraudulent bill. Always match an invoice to something you actually ordered.',
    detect: function (ctx) {
      return PA.scan(ctx.text, "(?:\\binvoice\\b|remittance|purchase order|pro forma|outstanding (?:balance|invoice|payment|amount)|past due|payment (?:is )?(?:due|overdue)|billing statement|amount due|final demand|unpaid (?:invoice|balance)|(?:invoice|statement|receipt) (?:is )?attached)", 4);
    }
  });

  /* =========================== social engineering =========================== */

  PA.GREETING_RE = "(?:dear (?:customer|client|user|member|valued (?:customer|client)|account holder|friend|sir or madam|sir/madam|candidate)|hi (?:there|friend)|hello(?: there| all| team| everyone)?|attention (?:customer|user|account holder)|dear all)";

  PA.extOf = function (name) {
    var m = /\.([a-z0-9]{1,8})$/.exec(String(name || '').toLowerCase().trim());
    return m ? m[1] : '';
  };

  PA.brandMentions = function (text) {
    var found = [];
    PA.BRANDS.forEach(function (b) {
      for (var i = 0; i < b.keys.length; i++) {
        var k = b.keys[i];
        var re = new RegExp("(?:^|[^a-z0-9])" + k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?:[^a-z0-9]|$)", "i");
        if (re.test(text) && found.indexOf(b.name) === -1) { found.push(b.name); break; }
      }
    });
    return found;
  };

  rule({
    id: 'urgency',
    title: 'Urgency and pressure language',
    weight: 12,
    severity: 'medium',
    category: 'Social engineering',
    why: "Urgency is the attacker's main tool: it pushes you to act before you think or check. Genuine organisations rarely impose sudden deadlines by email.",
    detect: function (ctx) {
      return PA.scan(ctx.text, "(?:\\burgent(?:ly)?\\b|immediately|act now|as soon as possible|\\basap\\b|right away|without delay|don[’']?t delay|time[- ]sensitive|limited time|final (?:notice|warning|reminder)|last (?:notice|warning|chance)|expires? (?:today|soon|in \\d+|within)|within \\d+ (?:hours?|minutes?|days?)|before it[’']?s too late|immediate action|(?:respond|reply|act|verify|confirm|update|pay|click) (?:now|today|immediately)|you must (?:act|respond|verify|confirm)|do not ignore|failure to (?:respond|comply)|avoid (?:suspension|closure|deactivation))", 6);
    }
  });

  rule({
    id: 'threat_suspension',
    title: 'Threatens account suspension or closure',
    weight: 15,
    severity: 'high',
    category: 'Social engineering',
    why: 'Threatening to close, lock or disable your account creates fear and pushes you to click without verifying. This is one of the most common phishing openers.',
    detect: function (ctx) {
      var a = PA.scan(ctx.text, "(?:suspend(?:ed|sion|ing)?|deactivat(?:e|ed|ion|ing)|terminat(?:e|ed|ion)|clos(?:e|ed|ure|ing)|lock(?:ed|ing)?|disabl(?:e|ed|ing)|restrict(?:ed|ing)?|deleted|blocked|frozen|expire[sd]?)[^.\n]{0,20}?\\b(?:account|access|profile|mailbox|subscription|membership|service)\\b", 4);
      var b = PA.scan(ctx.text, "\\b(?:account|access|profile|mailbox|subscription|membership|service)\\b[^.\n]{0,20}?(?:suspend(?:ed|sion|ing)?|deactivat(?:e|ed|ion)|terminat(?:e|ed|ion)|clos(?:e|ed|ure)|locked|disabl(?:e|ed)|restrict(?:ed)?|deleted|frozen|expire[sd]?)", 4);
      return a.concat(b);
    }
  });

  rule({
    id: 'impersonation',
    title: 'Claims to represent a known brand or an IT / security team',
    weight: 8,
    severity: 'medium',
    category: 'Impersonation',
    why: "Vague claims of authority ('the security team', 'Microsoft support') are used to make a message feel official. Real staff can be verified through a channel you already trust.",
    detect: function (ctx) {
      var evidence = [];
      var claimRe = new RegExp("(?:this is|we are|i am|on behalf of|from)[ ]+(?:the[ ]+)?(?:[a-z]+[ ]+){0,2}(?:security team|help ?desk|it department|it support|technical support|service desk|billing department|account team|fraud team|administrator)", "gi");
      var teamRe = new RegExp("(?:the[ ]+)?(?:security team|help ?desk|it support|technical support|service desk|billing department|account team|fraud team|administrator)", "i");
      var m;
      var guard = 0;
      while ((m = claimRe.exec(ctx.raw)) !== null && guard++ < 50) {
        evidence.push(m[0].replace(/[ ]+/g, ' ').trim());
        if (evidence.length > 3) break;
      }
      var CR = String.fromCharCode(13), LF = String.fromCharCode(10);
      var lines = ctx.raw.split(CR).join(LF).split(LF);
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (/^[A-Za-z][A-Za-z0-9-]*:/.test(line)) continue;
        if (line && line.length <= 46 && teamRe.test(line) && evidence.indexOf(line) === -1) {
          evidence.push(line);
          if (evidence.length > 4) break;
        }
      }
      var brands = PA.brandMentions(ctx.text);
      var hasGreeting = PA.contains(ctx.text, PA.GREETING_RE);
      if (brands.length && (hasGreeting || evidence.length)) {
        evidence = evidence.concat(brands.map(function (n) { return 'references ' + n; }));
      }
      return evidence;
    }
  });

  rule({
    id: 'generic_greeting',
    title: 'Impersonal, generic greeting',
    weight: 5,
    severity: 'low',
    category: 'Impersonation',
    why: "A message that opens with 'Dear Customer' rather than your real name suggests the sender does not actually know who you are — a strong hint that it was sent to thousands of people at once.",
    detect: function (ctx) {
      return PA.scan(ctx.text, PA.GREETING_RE, 2);
    }
  });

  /* =========================== dangerous attachments ======================== */

  rule({
    id: 'executable_attachment',
    title: 'Executable attachment',
    weight: 22,
    severity: 'high',
    category: 'Dangerous attachment',
    why: 'Executable files (.exe, .js, .scr and similar) run code on your computer when opened. They are one of the most common ways malware is delivered by email.',
    detect: function (ctx) {
      return ctx.attachments.filter(function (n) {
        return PA.DANGEROUS_EXT.indexOf(PA.extOf(n)) !== -1;
      });
    }
  });

  rule({
    id: 'macro_document',
    title: "Macro-enabled document or 'enable macros' request",
    weight: 18,
    severity: 'high',
    category: 'Dangerous attachment',
    why: "Macros are small programs embedded in Office documents. Attackers hide malware inside them, then persuade you to click 'Enable Content' or 'Enable Editing' so the code can run.",
    detect: function (ctx) {
      var evidence = [];
      ctx.attachments.forEach(function (n) {
        if (PA.MACRO_EXT.indexOf(PA.extOf(n)) !== -1) evidence.push(n);
      });
      var phrases = PA.scan(ctx.text, "(?:enable (?:macros|editing|content|protected view)|macros? (?:must|need to|have to) be (?:enabled|activated)|(?:click|allow) (?:enable )?(?:content|editing|macros)|disabl(?:e|ing) (?:macros|protected view))", 3);
      return phrases.concat(evidence);
    }
  });

  rule({
    id: 'double_extension',
    title: 'Attachment uses a double extension',
    weight: 12,
    severity: 'high',
    category: 'Dangerous attachment',
    why: "A file such as 'invoice.pdf.exe' is designed to look like a harmless document. If your computer hides file extensions you may only see 'invoice.pdf' — but it actually runs a program.",
    detect: function (ctx) {
      return PA.scan(ctx.text, "\\b[\\w\\- ]{1,40}\\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|html?|csv|rtf)\\.(?:exe|scr|js|jse|vbs|bat|cmd|com|pif|jar|msi|hta|lnk|zip|rar|7z|ps1|iso|img)\\b", 4);
    }
  });

  rule({
    id: 'archive_attachment',
    title: 'Password-protected or archive attachment',
    weight: 8,
    severity: 'medium',
    category: 'Dangerous attachment',
    why: 'Attackers often hide malware inside a ZIP or RAR file, sometimes protected with a password given in the email, because scanners cannot look inside encrypted archives.',
    detect: function (ctx) {
      var evidence = ctx.attachments.filter(function (n) {
        return PA.ARCHIVE_EXT.indexOf(PA.extOf(n)) !== -1;
      });
      if (evidence.length) {
        evidence = evidence.concat(PA.scan(ctx.text, "(?:password[- ]protected (?:zip|archive|file|attachment)|\\bthe password is\\b|\\bpassword[: ]+[a-z0-9]{3,20}\\b|encrypted (?:zip|archive|attachment))", 2));
      }
      return evidence;
    }
  });

  /* ================================ headers ================================= */

  rule({
    id: 'reply_to_mismatch',
    title: 'Reply-To address differs from the sender',
    weight: 18,
    severity: 'high',
    category: 'Header anomaly',
    why: "This is a favourite phishing trick: the message appears to come from one address, but any reply is quietly redirected somewhere else. Genuine bulk mail usually keeps the two consistent.",
    detect: function (ctx) {
      var h = ctx.headers;
      if (!h || !h.from || !h.replyTo) return [];
      var fromDomain = PA.domainOf(h.from);
      var replyDomain = PA.domainOf(h.replyTo);
      if (!fromDomain || !replyDomain || fromDomain === replyDomain) return [];
      return [h.from + '  →  replies go to  ' + h.replyTo];
    }
  });

  rule({
    id: 'spf_fail',
    title: 'SPF authentication failure',
    weight: 12,
    severity: 'high',
    category: 'Email authentication',
    why: "SPF records list the mail servers allowed to send email for a domain. A 'fail' result means this message did not come from the sender's real mail system — a common sign of spoofing. ('softfail' is weaker but still a warning.)",
    detect: function (ctx) {
      var v = ctx.headers && ctx.headers.spf;
      if (!v) return [];
      return /fail|permerror|temperror|softfail/.test(v) ? ['SPF: ' + v] : [];
    }
  });

  rule({
    id: 'dkim_fail',
    title: 'DKIM signature verification failure',
    weight: 10,
    severity: 'high',
    category: 'Email authentication',
    why: 'DKIM is a cryptographic signature that proves a message was really sent by the domain it claims. A failed signature means the message may have been altered or forged in transit.',
    detect: function (ctx) {
      var v = ctx.headers && ctx.headers.dkim;
      if (!v) return [];
      return /fail|permerror|temperror/.test(v) ? ['DKIM: ' + v] : [];
    }
  });

  rule({
    id: 'dmarc_fail',
    title: 'DMARC policy failure',
    weight: 12,
    severity: 'high',
    category: 'Email authentication',
    why: "DMARC ties SPF and DKIM together and tells mail providers what to do when a message fails. A DMARC failure is one of the strongest technical indicators that the sender address is not genuine.",
    detect: function (ctx) {
      var v = ctx.headers && ctx.headers.dmarc;
      if (!v) return [];
      return /fail|permerror|temperror|policy/.test(v) ? ['DMARC: ' + v] : [];
    }
  });

  /* =============================== links ==================================== */

  rule({
    id: 'raw_ip_url',
    title: 'Link uses a raw IP address instead of a domain name',
    weight: 20,
    severity: 'high',
    category: 'Suspicious link',
    why: 'Legitimate services use domain names (like example.com). A link built on a bare number such as 203.0.113.10 hides who really owns the site and is very rarely used for genuine business.',
    detect: function (ctx) {
      return ctx.links.filter(function (l) { return l.ip; }).map(function (l) { return l.href; });
    }
  });

  rule({
    id: 'shortened_url',
    title: 'Shortened link hides its true destination',
    weight: 10,
    severity: 'medium',
    category: 'Suspicious link',
    why: 'Link shorteners (bit.ly, t.co and similar) swap a long web address for a short one so you cannot see where you are being sent. They are widely used to conceal malicious sites.',
    detect: function (ctx) {
      return ctx.links.filter(function (l) { return l.shortener; }).map(function (l) { return l.href; });
    }
  });

  rule({
    id: 'punycode_domain',
    title: 'Link uses a look-alike internationalised domain',
    weight: 15,
    severity: 'high',
    category: 'Suspicious link',
    why: "Attackers can register domains using characters that look almost identical to ordinary letters (homograph spoofing). These appear as 'xn--' codes in the real address even though they may render as a familiar name.",
    detect: function (ctx) {
      return ctx.links.filter(function (l) { return l.punycode; }).map(function (l) { return l.host; });
    }
  });

  rule({
    id: 'lookalike_domain',
    title: 'Link domain imitates a known brand',
    weight: 15,
    severity: 'high',
    category: 'Suspicious link',
    why: 'The part of a web address immediately before the first single slash is the real site. Attackers put a trusted brand name earlier in the address (for example microsoft.com.login-example.test) so it looks official at a glance.',
    detect: function (ctx) {
      var out = [];
      ctx.links.forEach(function (l) { if (l.lookalike) out.push(l.host + '  (' + l.lookalike + ')'); });
      return out;
    }
  });

  rule({
    id: 'misleading_link_text',
    title: 'Link text does not match its destination',
    weight: 18,
    severity: 'high',
    category: 'Suspicious link',
    why: 'What you see is not always where you go. If the visible text of a link is a web address or a brand name that differs from the real destination, the link is deliberately misleading you.',
    detect: function (ctx) {
      var out = [];
      ctx.links.forEach(function (l) { if (l.mismatch) out.push('"' + l.text + '"  goes to  ' + l.host); });
      return out;
    }
  });

  /* ============================ recommendations ============================= */

  PA.BASE_RECOMMENDATIONS = [
    { text: 'Do not click any links or open any attachments in this email to see what happens. You do not need to test them to stay safe.', urgent: false },
    { text: 'Verify the message through a channel you already trust: type the organisation\'s official web address yourself, use its official app, or phone a number you already have. Never use contact details supplied in the email.', urgent: false }
  ];

  PA.CATEGORY_RECOMMENDATIONS = {
    'Credential theft': 'If you typed a password, or sent a verification code, anywhere after reading this email, change that password now and turn on multi-factor authentication.',
    'Fraud & payment': 'Confirm any payment, invoice or change of bank details by phoning the organisation on a number you already know. Never trust the bank details written in an email.',
    'Dangerous attachment': 'Do not open the attachment. Report the email to your IT or security team, then delete it — do not forward it on.',
    'Suspicious link': 'Treat the link as unsafe. Reach the organisation by typing its address yourself or through its official app, not by clicking.',
    'Email authentication': 'The technical checks that prove an email really came from the sender failed. Treat the displayed sender address as untrustworthy, no matter how convincing it looks.',
    'Header anomaly': 'The routing information in the email does not add up. Compare the From and Reply-To addresses carefully before trusting the sender.',
    'Impersonation': 'Do not trust the name or brand in the email. Confirm the person or organisation independently before replying or acting.',
    'Social engineering': 'Slow down. Pressure and deadlines are the attacker\'s tools — take the time to verify before you act.'
  };

  PA.buildRecommendations = function (findings) {
    var recos = [];
    var seen = {};
    var urgentCats = ['Credential theft', 'Fraud & payment', 'Dangerous attachment', 'Email authentication', 'Header anomaly'];
    findings.forEach(function (f) {
      if (seen[f.category]) return;
      seen[f.category] = true;
      if (PA.CATEGORY_RECOMMENDATIONS[f.category]) {
        recos.push({ text: PA.CATEGORY_RECOMMENDATIONS[f.category], urgent: urgentCats.indexOf(f.category) !== -1 });
      }
    });
    if (!recos.length) {
      recos.push({ text: 'No specific action stands out, but keep the general habits: verify unexpected requests, and never use the contact details supplied in an email.', urgent: false });
    }
    recos = recos.concat(PA.BASE_RECOMMENDATIONS);
    recos.push({ text: 'Report suspected phishing to your IT or security team, or to your national reporting service (for example the NCSC in the UK or the FTC in the US). Reporting helps protect everyone.', urgent: false });
    return recos;
  };
})();
