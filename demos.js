/* ==========================================================================
   demos.js — the fictional demonstration emails
   --------------------------------------------------------------------------
   Every address, domain and URL below is deliberately fake or reserved:
     * .test / .example  — reserved by RFC 2606 (they can never be registered)
     * 203.0.113.x       — a reserved documentation range (not routable)
   None of these links do anything at all. The text is only ever compared as
   plain text — it is never rendered as HTML, so nothing is clickable, fetched
   or opened. They exist purely so you can practise spotting the warning signs.
   ========================================================================== */

(function () {
  'use strict';

  var PA = (window.PA = window.PA || {});
  var LF = String.fromCharCode(10);

  PA.DEMOS = [];

  PA.DEMOS.push({
    id: 'obvious-phishing',
    name: 'Obvious phishing',
    tone: 'high',
    expected: 'high',
    blurb: 'Classic panic email: threats, a deadline and an outright request for your password.',
    body: [
      'Subject: URGENT: Your account will be SUSPENDED within 24 hours!',
      '',
      'From: "Account Security" <security@secure-example-login.test>',
      'Reply-To: recover@secure-example-login.test',
      '',
      'Dear Customer,',
      '',
      'We have detected unusual sign-in activity on your account. Your account will be',
      'suspended and permanently closed within 24 hours unless you verify your account',
      'immediately.',
      '',
      'To keep your access you must confirm your identity right now. Please reply to this',
      'email with your password, and send the one-time verification code that we just sent',
      'to your phone.',
      '',
      '[Verify my account now](http://microsoft.com.secure-example-login.test/verify)',
      'Backup link: http://203.0.113.45/account/verify',
      '',
      'Failure to comply will result in permanent closure of your mailbox.',
      '',
      'The Security Team'
    ].join(LF)
  });

  PA.DEMOS.push({
    id: 'sophisticated-phishing',
    name: 'Sophisticated phishing',
    tone: 'medium',
    expected: 'suspicious',
    blurb: 'No panic words and no threats — just a quiet request to update supplier bank details.',
    body: [
      'Subject: Remittance advice — please update our payment details',
      '',
      'From: "Accounts Payable" <ap@example-invoices.test>',
      'Reply-To: ap@example-invoices.test',
      '',
      'Hello,',
      '',
      'Thank you again for your continuing work with us this quarter. Attached is the',
      'remittance advice for your latest invoice, together with a revised supplier form.',
      '',
      'Please note that our bank details have changed for future payments. The new account',
      'number is on page two of the attached statement, so nothing needs doing beyond',
      'updating your supplier records when convenient.',
      '',
      'Our accounts portal is here if you would like to check anything:',
      '[accounts.example-invoices.test](http://example-invoices.test.portal-secure.test/login)',
      '',
      'Kind regards,',
      'Accounts Payable'
    ].join(LF)
  });

  PA.DEMOS.push({
    id: 'fake-microsoft-365',
    name: 'Fake Microsoft 365 warning',
    tone: 'high',
    expected: 'high',
    blurb: 'A spoofed Microsoft notification where the SPF, DKIM and DMARC checks all fail.',
    body: [
      'Return-Path: <bounce@example-mailer.test>',
      'Received-SPF: fail (domain of example-mailer.test does not designate 203.0.113.77 as permitted sender)',
      'Authentication-Results: spf=fail smtp.mailfrom=microsoft-verify.example;',
      '  dkim=fail header.d=microsoft-verify.example;',
      '  dmarc=fail header.from=microsoft-verify.example',
      'From: "Microsoft 365" <no-reply@microsoft-verify.example>',
      'Reply-To: support@microsoft-helpdesk.example',
      'To: undisclosed-recipients:;',
      'Subject: Action required: we blocked a sign-in to your mailbox',
      '',
      'Dear User,',
      '',
      'We blocked a sign-in attempt to your Microsoft 365 mailbox from an unrecognised',
      'device.',
      '',
      'To restore your access you must verify your account within 24 hours, otherwise your',
      'mailbox will be deactivated.',
      '',
      '[Sign in to continue](http://login.microsoft-verify.example.auth-check.test/session)',
      '',
      'Thank you,',
      'The Microsoft 365 Security Team'
    ].join(LF)
  });

  PA.DEMOS.push({
    id: 'parcel-delivery',
    name: 'Fake parcel delivery',
    tone: 'high',
    expected: 'high',
    blurb: 'A delivery scam built on a short link, a small "redelivery fee" and a gift-card option.',
    body: [
      'Subject: We missed you — your item is waiting (ref PD-8841)',
      '',
      'From: "Royal Mail" <no-reply@royalmaill.example>',
      'Reply-To: delivery@royalmaill.example',
      '',
      'Hello,',
      '',
      'We tried to deliver your item today but there was no answer. Please confirm your',
      'delivery details and settle the £1.99 handling fee within 48 hours, otherwise your',
      'item will be returned to the sorting office.',
      '',
      'Reschedule here: [royalmail.com](http://royalmaill.example.track-item.test/redelivery)',
      'Short link: http://bit.ly/example-not-a-real-code',
      '',
      'Payment can be made by debit card, or by gift card if that is easier for you.',
      '',
      'Kind regards,',
      'Royal Mail Customer Service'
    ].join(LF)
  });

  PA.DEMOS.push({
    id: 'invoice-bec',
    name: 'Fake invoice (BEC style)',
    tone: 'medium',
    expected: 'high',
    blurb: 'Impersonation of a colleague asking for an urgent, confidential payment.',
    body: [
      'Authentication-Results: spf=pass smtp.mailfrom=example-group.example; dkim=none; dmarc=none',
      'From: "Jonathan Reynolds (CEO)" <j.reynolds@example-group.example>',
      'Reply-To: j.reynolds.private@example-group-private.example',
      'To: finance@our-company.example',
      'Subject: Quick favour — confidential',
      '',
      'Hi,',
      '',
      'I am in back-to-back meetings so please reply by email only and do not call.',
      '',
      'We are completing an acquisition and I need you to process an urgent payment today.',
      'Our bank details have changed for this transaction — the new account is shown on the',
      'invoice attached.',
      '',
      'Please keep this confidential and do not discuss it with the wider team.',
      '',
      'Invoice: invoice-2026-0147.pdf',
      '',
      'Thanks,',
      'Jonathan'
    ].join(LF)
  });

  PA.DEMOS.push({
    id: 'legitimate',
    name: 'Legitimate email',
    tone: 'low',
    expected: 'low',
    blurb: 'An everyday internal email that should score close to zero.',
    body: [
      'From: "Sarah Chen" <sarah.chen@example-corp.example>',
      'To: "Alex Morgan" <alex.morgan@example-corp.example>',
      'Subject: Notes from Tuesday security awareness session',
      '',
      'Hi Alex,',
      '',
      'Thanks for joining the awareness session on Tuesday — the questions from your team',
      'were excellent.',
      '',
      'As promised, here are the main points we agreed:',
      '  * Slow down before acting on an unexpected request.',
      '  * Check the sender address, not just the display name.',
      '  * Reach a website by typing the address yourself.',
      '  * Report anything suspicious to IT rather than deleting it.',
      '',
      'There is nothing you need to do from this email. If you would like the slide deck,',
      'it is in the usual shared folder.',
      '',
      'Best wishes,',
      'Sarah'
    ].join(LF)
  });


  PA.getDemo = function (id) {
    for (var i = 0; i < PA.DEMOS.length; i++) {
      if (PA.DEMOS[i].id === id) return PA.DEMOS[i];
    }
    return null;
  };
})();
