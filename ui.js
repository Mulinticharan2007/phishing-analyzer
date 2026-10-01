/* ==========================================================================
   ui.js — screen wiring
   --------------------------------------------------------------------------
   All the code here only touches the page. It reads the text box, calls
   PA.analyse() and draws the result.

   SAFETY NOTE: e-mail text is only ever inserted with textContent (never
   innerHTML), so a malicious message cannot inject markup or scripts into
   this page.
   ========================================================================== */

(function () {
  'use strict';

  var PA = window.PA;

  var els = {};

  function $(id) { return document.getElementById(id); }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  var BAND_COLOUR = { low: '#35c98a', suspicious: '#f5a623', high: '#ff5470' };

  var ICON_TICK = 'M9.6 16.3 5.3 12l1.4-1.5 2.9 2.9 7.7-7.7 1.4 1.4z';
  var ICON_WARN = 'M12 2.3 1.8 20.5h20.4L12 2.3zm0 4.6 6.6 11.8H5.4L12 6.9zM11.2 9.8h1.6v5h-1.6v-5zm0 6.1h1.6v1.6h-1.6v-1.6z';

  function svgIcon(pathData, size, colour) {
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', String(size || 18));
    svg.setAttribute('height', String(size || 18));
    svg.setAttribute('aria-hidden', 'true');
    var p = document.createElementNS(NS, 'path');
    p.setAttribute('fill', colour || 'currentColor');
    p.setAttribute('d', pathData);
    svg.appendChild(p);
    return svg;
  }

  /* ------------------------------------------------------------- start up --- */

  function init() {
    els.input = $('emailInput');
    els.analyseBtn = $('analyseBtn');
    els.clearBtn = $('clearBtn');
    els.printBtn = $('printBtn');
    els.demoList = $('demoList');
    els.resultEmpty = $('resultEmpty');
    els.resultContent = $('resultContent');
    els.resultPanel = $('resultPanel');
    els.selfTestToggle = $('selfTestToggle');
    els.selfTestPanel = $('selfTestPanel');
    els.selfTestOutput = $('selfTestOutput');

    if (!PA || !PA.analyse) {
      showFatal('The analysis engine did not load. Please reload the page.');
      return;
    }

    renderDemos();

    els.analyseBtn.addEventListener('click', runAnalysis);
    els.clearBtn.addEventListener('click', clearAll);
    els.printBtn.addEventListener('click', function () { window.print(); });
    els.selfTestToggle.addEventListener('click', toggleSelfTests);

    els.input.addEventListener('keydown', function (ev) {
      if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') {
        ev.preventDefault();
        runAnalysis();
      }
    });
  }

  function showFatal(message) {
    if (!els.resultContent) return;
    els.resultContent.hidden = false;
    els.resultContent.textContent = '';
    els.resultContent.appendChild(el('p', 'clean-note', message));
    if (els.resultEmpty) els.resultEmpty.hidden = true;
  }

  function renderDemos() {
    if (!els.demoList || !PA.DEMOS) return;
    for (var i = 0; i < PA.DEMOS.length; i++) {
      (function (demo) {
        var btn = el('button', 'demo-btn');
        btn.type = 'button';
        var swatch = el('span', 'swatch');
        swatch.style.background = BAND_COLOUR[demo.tone] || '#7b89a8';
        btn.appendChild(swatch);
        btn.appendChild(document.createTextNode(demo.name));
        btn.title = demo.blurb;
        btn.addEventListener('click', function () { loadDemo(demo); });
        els.demoList.appendChild(btn);
      }(PA.DEMOS[i]));
    }
  }

  function loadDemo(demo) {
    els.input.value = demo.body;
    els.input.focus();
    runAnalysis();
  }

  function clearAll() {
    els.input.value = '';
    els.input.focus();
    els.resultContent.hidden = true;
    els.resultContent.textContent = '';
    els.resultEmpty.hidden = false;
    els.printBtn.disabled = true;
  }

  /* --------------------------------------------------------- the analysis --- */

  function runAnalysis() {
    var text = els.input.value;
    els.printBtn.disabled = true;

    if (!text || !text.replace(/\s+/g, '')) {
      els.resultContent.hidden = true;
      els.resultContent.textContent = '';
      els.resultEmpty.hidden = false;
      els.input.focus();
      return;
    }

    var res;
    try {
      res = PA.analyse(text);
    } catch (err) {
      showFatal('Sorry — the analyser hit an unexpected problem reading that text. Please check the pasted content and try again.');
      return;
    }

    renderResult(res);
    els.printBtn.disabled = false;
  }

  function verdictTitle(res) {
    var n = res.findings.length;
    if (!n) return 'No known warning signs detected';
    if (res.band.id === 'low') return n + ' minor warning sign' + (n === 1 ? '' : 's') + ' noted';
    return n + ' warning sign' + (n === 1 ? '' : 's') + ' detected';
  }

  function renderResult(res) {
    var colour = BAND_COLOUR[res.band.id] || '#7b89a8';
    els.resultContent.textContent = '';
    els.resultContent.hidden = false;
    els.resultEmpty.hidden = true;

    var head = el('div', 'result-head');
    head.appendChild(buildGauge(res.score, colour));

    var body = el('div', 'result-body');
    var band = el('span', 'band band-' + res.band.id);
    band.appendChild(el('span', 'band-dot'));
    band.appendChild(document.createTextNode(res.band.label));
    body.appendChild(band);
    body.appendChild(el('h3', 'result-title', verdictTitle(res)));
    body.appendChild(el('p', 'result-summary', res.band.summary));
    body.appendChild(buildStats(res));
    head.appendChild(body);
    els.resultContent.appendChild(head);

    els.resultContent.appendChild(buildFindings(res));
    els.resultContent.appendChild(buildRecommendations(res));
    els.resultContent.appendChild(buildDisclaimer());

    els.printBtn.disabled = false;

    if (window.innerWidth < 940 && els.resultPanel.scrollIntoView) {
      els.resultPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function buildStats(res) {
    var row = el('div', 'stat-row');
    var st = res.stats;

    row.appendChild(chip('warning signs:', res.findings.length));
    row.appendChild(chip('links checked:', st.linkCount));
    row.appendChild(chip('attachments:', st.attachmentCount));

    if (st.hosts.length) {
      row.appendChild(chip('link domains:', st.hosts.slice(0, 3).join(', ') +
        (st.hosts.length > 3 ? ' (+' + (st.hosts.length - 3) + ' more)' : '')));
    }

    var h = st.headers;
    if (h && h.present) {
      var parts = [];
      if (h.spf) parts.push('SPF ' + h.spf);
      if (h.dkim) parts.push('DKIM ' + h.dkim);
      if (h.dmarc) parts.push('DMARC ' + h.dmarc);
      row.appendChild(chip('mail checks:', parts.length ? parts.join(', ') : 'headers found'));
    } else {
      row.appendChild(chip('mail headers:', 'not provided'));
    }

    if (res.capped) row.appendChild(chip('note:', 'score capped at 100'));
    return row;
  }

  function chip(label, value) {
    var s = el('span', 'stat');
    s.appendChild(document.createTextNode(label + ' '));
    s.appendChild(el('strong', null, value));
    return s;
  }

  function buildGauge(score, colour) {
    var NS = 'http://www.w3.org/2000/svg';
    var wrap = el('div', 'gauge');

    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 120 120');
    svg.setAttribute('width', '138');
    svg.setAttribute('height', '138');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Phishing risk score ' + score + ' out of 100');

    var r = 52;
    var c = 2 * Math.PI * r;

    var track = document.createElementNS(NS, 'circle');
    track.setAttribute('cx', '60');
    track.setAttribute('cy', '60');
    track.setAttribute('r', String(r));
    track.setAttribute('fill', 'none');
    track.setAttribute('stroke-width', '11');
    track.setAttribute('class', 'gauge-track');

    var val = document.createElementNS(NS, 'circle');
    val.setAttribute('cx', '60');
    val.setAttribute('cy', '60');
    val.setAttribute('r', String(r));
    val.setAttribute('fill', 'none');
    val.setAttribute('stroke-width', '11');
    val.setAttribute('stroke-linecap', 'round');
    val.setAttribute('stroke', colour);
    val.setAttribute('class', 'gauge-value');
    val.setAttribute('stroke-dasharray', String(c));
    val.setAttribute('stroke-dashoffset', String(c));

    svg.appendChild(track);
    svg.appendChild(val);
    wrap.appendChild(svg);

    var centre = el('div', 'gauge-center');
    var num = el('span', 'gauge-score', String(score));
    num.style.color = colour;
    centre.appendChild(num);
    centre.appendChild(el('span', 'gauge-of', 'OUT OF 100'));
    wrap.appendChild(centre);

    window.setTimeout(function () {
      val.setAttribute('stroke-dashoffset', String(c * (1 - score / 100)));
    }, 60);

    return wrap;
  }


  /* ------------------------------------------------------------- findings --- */

  function buildFindings(res) {
    var block = el('div', 'block');
    var head = el('div', 'block-head');
    head.appendChild(el('h3', null, 'Why this score'));
    var total = (PA.RULES && PA.RULES.length) ? PA.RULES.length : 0;
    head.appendChild(el('span', 'count',
      res.findings.length ? res.findings.length + ' of ' + total + ' checks matched' : 'no checks matched'));
    block.appendChild(head);

    if (!res.findings.length) {
      var note = el('div', 'clean-note');
      note.appendChild(el('strong', null, 'No known warning signs were found in this text. '));
      note.appendChild(document.createTextNode(
        'That is reassuring, but it is not a guarantee. A carefully written phishing email can contain ' +
        'none of the signs this tool looks for. Trust your judgement, and verify anything unexpected.'));
      block.appendChild(note);
      return block;
    }

    for (var i = 0; i < res.findings.length; i++) {
      var f = res.findings[i];
      var card = el('div', 'finding finding-sev-' + f.severity);

      var top = el('div', 'finding-top');
      top.appendChild(el('h4', 'finding-title', f.title));
      top.appendChild(el('span', 'finding-points', '+' + f.weight));
      card.appendChild(top);

      card.appendChild(el('p', 'finding-cat', f.category + '  \u00b7  adds ' + f.weight + ' of 100 points'));
      card.appendChild(el('p', 'finding-why', f.why));

      if (f.evidence.length) {
        card.appendChild(el('p', 'evidence-label', 'What we matched in your text'));
        var ul = el('ul', 'finding-evidence');
        for (var e = 0; e < f.evidence.length; e++) {
          ul.appendChild(el('li', null, f.evidence[e]));
        }
        card.appendChild(ul);
      }
      block.appendChild(card);
    }
    return block;
  }

  /* ------------------------------------------------------ recommendations --- */

  function buildRecommendations(res) {
    var block = el('div', 'block');
    var head = el('div', 'block-head');
    head.appendChild(el('h3', null, 'What to do next'));
    block.appendChild(head);

    var ul = el('ul', 'reco-list');
    for (var i = 0; i < res.recommendations.length; i++) {
      var r = res.recommendations[i];
      var li = el('li', r.urgent ? 'reco-urgent' : '');
      var mark = el('span', 'reco-mark');
      mark.appendChild(svgIcon(r.urgent ? ICON_WARN : ICON_TICK, 18));
      li.appendChild(mark);
      li.appendChild(el('span', null, r.text));
      ul.appendChild(li);
    }
    block.appendChild(ul);
    return block;
  }

  function buildDisclaimer() {
    var box = el('div', 'disclaimer-box');
    box.appendChild(el('h4', null, 'Please read this before acting on the result'));

    var p1 = el('p');
    p1.appendChild(document.createTextNode('This tool is an '));
    p1.appendChild(el('strong', null, 'educational triage aid'));
    p1.appendChild(document.createTextNode(
      '. It identifies warning signs. It cannot prove an email is malicious, and it cannot prove one is safe, ' +
      'so a low score is not a guarantee.'));
    box.appendChild(p1);

    box.appendChild(el('p', null,
      'Never click a suspicious link or open an attachment to see what it does. Verify important messages ' +
      'through an organisation\'s official website, its official app, or a phone number you already trust ' +
      '\u2014 never through the contact details supplied in the email itself.'));

    box.appendChild(el('p', null,
      'Your email was analysed entirely inside this browser. Nothing was uploaded, stored, logged, ' +
      'sent to an AI service or shared with anyone.'));
    return box;
  }

  /* ------------------------------------------------------------ self-tests --- */

  function toggleSelfTests() {
    var open = els.selfTestPanel.hidden;
    els.selfTestPanel.hidden = !open;
    els.selfTestToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open && PA.renderSelfTests) {
      PA.renderSelfTests(els.selfTestOutput);
      if (els.selfTestPanel.scrollIntoView) {
        els.selfTestPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

