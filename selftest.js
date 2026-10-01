/* ==========================================================================
   selftest.js — the built-in self-tests
   --------------------------------------------------------------------------
   These tests run the real analyser against the fictional examples and a few
   synthetic snippets, then check the expected outcome. They run in your
   browser, on demand, and print pass/fail into the page. Nothing is uploaded.
   ========================================================================== */

(function () {
  'use strict';

  var PA = (window.PA = window.PA || {});

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function hasFinding(res, id) {
    for (var i = 0; i < res.findings.length; i++) {
      if (res.findings[i].id === id) return true;
    }
    return false;
  }

  function demoBody(id) {
    var d = PA.getDemo ? PA.getDemo(id) : null;
    if (!d) throw new Error('demo "' + id + '" is missing');
    return d.body;
  }

  /* Each test returns true (pass), or an object { pass: bool, detail: string }.
     Throwing inside a test counts as a failure. */
  PA.runSelfTests = function () {
    var results = [];

    function check(name, fn) {
      var r;
      try {
        r = fn();
      } catch (err) {
        results.push({ name: name, pass: false,
          detail: (err && err.name ? err.name + ': ' : '') + (err && err.message ? err.message : String(err)) });
        return;
      }
      if (r === true) { results.push({ name: name, pass: true, detail: '' }); return; }
      if (r && typeof r === 'object') {
        results.push({ name: name, pass: !!r.pass, detail: r.detail || '' });
        return;
      }
      results.push({ name: name, pass: false, detail: 'unexpected test result' });
    }

    /* ------------------------------------------------ each example scores --- */

    check('Every fictional example produces its expected classification', function () {
      var bad = [];
      for (var i = 0; i < PA.DEMOS.length; i++) {
        var d = PA.DEMOS[i];
        var res = PA.analyse(d.body);
        if (res.band.id !== d.expected) {
          bad.push(d.name + ' scored ' + res.score + ' (' + res.band.label + '), expected ' + d.expected);
        }
      }
      return bad.length ? { pass: false, detail: bad.join('; ') } : true;
    });

    check('The legitimate example scores zero and is classified Low Risk', function () {
      var res = PA.analyse(demoBody('legitimate'));
      return { pass: res.score === 0 && res.band.id === 'low',
        detail: 'score ' + res.score + ', ' + res.findings.length + ' findings' };
    });

    /* ------------------------------------------------------- score bands --- */

    check('Score bands are correct at their boundaries', function () {
      var cases = [[0, 'low'], [24, 'low'], [25, 'suspicious'], [59, 'suspicious'], [60, 'high'], [100, 'high']];
      var bad = [];
      for (var i = 0; i < cases.length; i++) {
        var got = PA.bandForScore(cases[i][0]).id;
        if (got !== cases[i][1]) bad.push(cases[i][0] + ' -> ' + got + ' (expected ' + cases[i][1] + ')');
      }
      return bad.length ? { pass: false, detail: bad.join('; ') } : true;
    });

    check('An empty message scores zero', function () {
      return PA.analyse('').score === 0;
    });

    /* ----------------------------------------------------- individual signs --- */

    check('Detects a request for a password', function () {
      return hasFinding(PA.analyse(demoBody('obvious-phishing')), 'password_request');
    });

    check('Detects a request for an MFA / verification code', function () {
      return hasFinding(PA.analyse(demoBody('obvious-phishing')), 'mfa_code_request');
    });

    check('Detects a link that uses a raw IP address', function () {
      return hasFinding(PA.analyse('Please log in here: http://198.51.100.9/login'), 'raw_ip_url');
    });

    check('Detects a shortened link', function () {
      return hasFinding(PA.analyse('Track it here: http://bit.ly/example-code'), 'shortened_url');
    });

    check('Detects a domain that imitates a brand', function () {
      return hasFinding(PA.analyse('Log in at http://paypa1.example/login'), 'lookalike_domain');
    });

    check('Detects a look-alike (punycode) domain', function () {
      return hasFinding(PA.analyse('Log in at http://xn--pypal-4ve.example/login'), 'punycode_domain');
    });

    check('Detects link text that does not match its destination', function () {
      return hasFinding(PA.analyse('[apple.com](http://account-check.example/login)'), 'misleading_link_text');
    });

    check('Detects a gift-card or cryptocurrency payment request', function () {
      return hasFinding(PA.analyse('Please settle this today with a gift card.'), 'gift_card_payment');
    });

    check('Detects a request to change bank details', function () {
      return hasFinding(PA.analyse('Please note our bank details have changed for future invoices.'), 'bank_detail_change');
    });

    check('Detects a Reply-To address that differs from the sender', function () {
      var msg = ['From: "Billing" <billing@example-a.test>', 'Reply-To: billing@example-b.test', '',
                 'Your invoice is attached.'].join(String.fromCharCode(10));
      return hasFinding(PA.analyse(msg), 'reply_to_mismatch');
    });

    check('Detects failed SPF, DKIM and DMARC results in pasted headers', function () {
      var msg = ['Authentication-Results: spf=fail smtp.mailfrom=example.test;',
                 '  dkim=fail header.d=example.test;',
                 '  dmarc=fail header.from=example.test',
                 'From: no-reply@example.test', '',
                 'Please verify your account.'].join(String.fromCharCode(10));
      var res = PA.analyse(msg);
      var ok = hasFinding(res, 'spf_fail') && hasFinding(res, 'dkim_fail') && hasFinding(res, 'dmarc_fail');
      return { pass: ok, detail: ok ? '' : 'matched ' + res.findings.length + ' rules' };
    });

    check('Detects an executable attachment', function () {
      return hasFinding(PA.analyse('The attached file update.exe is ready.'), 'executable_attachment');
    });

    check('Detects a double-extension attachment', function () {
      return hasFinding(PA.analyse('Please open invoice.pdf.exe to see your statement.'), 'double_extension');
    });

    check('Detects a macro-enabled document or an "enable macros" request', function () {
      return hasFinding(PA.analyse('You must enable macros to view the attached Statement.docm file.'), 'macro_document');
    });


    /* ------------------------------------------------------- false alarms --- */

    check('An ordinary invoice email is not over-flagged', function () {
      var res = PA.analyse('Hi Sam, the invoice for last month is attached. Thanks, Priya');
      return { pass: res.band.id === 'low', detail: 'scored ' + res.score };
    });

    check('An ordinary "please verify your email address" sign-up is not High Risk', function () {
      var res = PA.analyse('Welcome! Please verify your email address to finish setting up your account. No action is needed today.');
      return { pass: res.band.id !== 'high', detail: 'scored ' + res.score };
    });

    /* ------------------------------------------------------------ privacy --- */

    check('Analysing an email makes no network requests', function () {
      var calls = 0;
      var origFetch = window.fetch;
      var OrigXHR = window.XMLHttpRequest;
      var origBeacon = navigator.sendBeacon;
      var origImage = window.Image;

      window.fetch = function () { calls++; return origFetch ? origFetch.apply(window, arguments) : null; };
      if (OrigXHR) { window.XMLHttpRequest = function () { calls++; }; }
      if (origBeacon) { navigator.sendBeacon = function () { calls++; return true; }; }
      window.Image = function () { calls++; };

      try {
        PA.analyse(demoBody('obvious-phishing'));
      } finally {
        window.fetch = origFetch;
        if (OrigXHR) { window.XMLHttpRequest = OrigXHR; }
        if (origBeacon) { navigator.sendBeacon = origBeacon; }
        window.Image = origImage;
      }
      return { pass: calls === 0, detail: calls ? calls + ' network call(s) were made' : '' };
    });

    check('The page does not reference any external resource', function () {
      var bad = [];
      var nodes = document.querySelectorAll('script[src], link[href], img[src], iframe[src], source[src]');
      for (var i = 0; i < nodes.length; i++) {
        var url = nodes[i].getAttribute('src') || nodes[i].getAttribute('href') || '';
        if (url.indexOf('http://') === 0 || url.indexOf('https://') === 0 || url.indexOf('//') === 0) {
          bad.push(url);
        }
      }
      return { pass: bad.length === 0, detail: bad.length ? 'found: ' + bad.join(', ') : '' };
    });

    return results;
  };

  /* --------------------------------------------------------- the on-screen --- */

  PA.renderSelfTests = function (container) {
    if (!container) return [];
    var results = PA.runSelfTests();
    var passed = 0;
    var i;

    for (i = 0; i < results.length; i++) { if (results[i].pass) passed++; }

    container.textContent = '';

    var allPassed = passed === results.length;
    var summary = el('p', 'test-summary',
      passed + ' of ' + results.length + ' checks passed' +
      (allPassed ? ' — everything looks healthy.' : ' — please review the failures below.'));
    summary.style.color = allPassed ? '#a6f0cd' : '#ffb6c3';
    container.appendChild(summary);

    for (i = 0; i < results.length; i++) {
      var r = results[i];
      var row = el('div', 'test-row ' + (r.pass ? 'test-pass' : 'test-fail'));
      row.appendChild(el('span', 'test-badge', r.pass ? 'Pass' : 'Fail'));
      var body = el('div');
      body.appendChild(el('div', 'test-name', r.name));
      if (r.detail) body.appendChild(el('p', 'test-detail', r.detail));
      row.appendChild(body);
      container.appendChild(row);
    }
    return results;
  };
})();

