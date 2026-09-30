/* ------------------------------------------------------------------ *
 * Cyber Shield Zimbabwe - rule engine
 * Pure text analysis. No DOM access.
 * ------------------------------------------------------------------ */

// [pattern, class weights, risk weight, reason]
// classes: phish, fin, id, link, ai
const RULES = [
  [/\b(password|passcode)\b/i, { id: 2 }, 2, 'Asks for your password'],
  [/\b(otp|one[- ]time (pin|code)|verification code)\b/i, { id: 3 }, 3, 'Asks for a one-time code (OTP)'],
  [/\bpin\b/i, { fin: 3 }, 3, 'Asks for your PIN'],
  [/national id|id number|passport|personal details|account details/i, { id: 2 }, 1.5, 'Asks for identity or account details'],
  [/\b(won|winner|prize|congratulations|lottery|giveaway|bonus|jackpot)\b/i, { fin: 2 }, 2.5, 'Unexpected prize or reward'],
  [/send money|transfer|new account|bank details|card number|payment (has )?failed|reverse the transaction|loan|investment/i, { fin: 2 }, 2, 'Money or payment request'],
  [/mobile money|ecocash|onemoney|innbucks/i, { fin: 1 }, 1, 'Mentions mobile money'],
  [/https?:\/\/\S+|www\.\S+|bit\.ly\S*|tinyurl\S*/i, { link: 4 }, 2, 'Contains a web link'],
  [/link below|click( here| the link)?\b|tap here/i, { link: 1, phish: 1 }, 1, 'Pushes you to click'],
  [/download|\.apk\b|\.exe\b|\.zip\b/i, { link: 2 }, 1.5, 'Asks you to download a file'],
  [/attached|attachment/i, { link: 1 }, 1, 'Has an attachment'],
  [/suspend|disabled|deactivat|locked|storage is full|mailbox (is )?full|will expire|will be (closed|blocked|deleted)|account (closure|closed)|verify your|restore your account/i, { phish: 3 }, 2, 'Threatens to close or lock your account'],
  [/(verify|confirm|validate|update|re-?activate)\s+(your\s+)?(account|details|identity|profile|number)/i, { phish: 2 }, 1.5, 'Asks you to "verify" or "update" your account'],
  [/sign in|log ?in\b/i, { phish: 1 }, 1, 'Asks you to log in'],
  [/urgent|immediately|\btoday\b|\bnow\b|asap|within \d+ (hours|minutes)/i, {}, 1, 'Creates pressure to act fast'],
  [/voice message|voice note|\bvideo\b|deepfake|appears to show|sounds like|\b(manager|boss|ceo|director|minister|president|official)\b/i, { ai: 2 }, 1, 'May imitate a trusted person or official'],
  [/reply with|send your|enter your|share your/i, { id: 1 }, 1, 'Asks you to hand over details'],

  // Shona and Ndebele cues. English-only rules miss a large share of the
  // scams that reach people on WhatsApp in Harare and Bulawayo, so the
  // highest-signal local phrases are matched here too.
  [/\b(nditumire|ndiudze|ndiuyarire|nditumire)\b/i, { id: 2 }, 2, 'Shona: asks you to send or hand over something'],
  [/\b(chikomo chako|password yako|pini yako|otu yako|chiitika chako)\b/i, { id: 3 }, 3, 'Shona: asks for your login or PIN'],
  [/\b(mari yako|mafemo|mukwero wako)\b/i, { fin: 2 }, 2, 'Shona: asks for your money or banking details'],
  [/\b(chikumo|zvinyoronyoro zvechizita|hasha)\b/i, { id: 2 }, 1.5, 'Shona: refers to an identity document'],
  [/\b(tinya|vhura ihabhumbo|chindyengero)\b/i, { link: 2, phish: 1 }, 1.5, 'Shona: pushes you to open a link'],
  [/\b(mhaka|boss|mudzvanyiriri|mutumiri|mukuru)\b/i, { ai: 2 }, 1, 'Shona: may imitate a person in authority'],
  [/\b(ngicela|ngithumele|ngifuna|ngifunele)\b/i, { id: 2 }, 2, 'Ndebele: asks you to send or hand over something'],
  [/\b(i-akhawunti yami|upassword lwami|iphini yami)\b/i, { id: 3 }, 3, 'Ndebele: asks for your login or PIN'],
  [/\b(imali yami|imali yenkampani)\b/i, { fin: 2 }, 2, 'Ndebele: asks for your money or banking details'],
  [/\b(uceli|chofo|isixhumi|ikhasini)\b/i, { link: 2, phish: 1 }, 1.5, 'Ndebele: pushes you to open a link'],
  [/\b(umholi|uphathi|uhlmenyathi|umuntu)\b/i, { ai: 2 }, 1, 'Ndebele: may imitate a person in authority'],
];

const RULE_COUNT = RULES.length;

// Phrases that make an otherwise alarming message look legitimate.
const BENIGN = [
  /do not share (it|this|your)|never share|was (received|successful)|thank you for|see you\b|moved to \d|your otp is \d/i,
  /appointment.*confirmed|timetable|usual .*portal|standard login|meeting (at|on)/i,
];

// Chat shorthand that hides meaning.
const ABBREV = {
  ur: 'your', u: 'you', acct: 'account', acc: 'account', pls: 'please',
  plz: 'please', info: 'details', cnfrm: 'confirm', pwd: 'password',
  pswd: 'password',
};

// Leetspeak substitutions.
const LEET = { 0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', '@': 'a', $: 's' };

// Brand -> its real official domain, used to catch lookalike sites.
const BRANDS = {
  ecocash: 'ecocash.co.zw',
  econet: 'econet.co.zw',
  netone: 'netone.co.zw',
  telone: 'telone.co.zw',
  cbz: 'cbz.co.zw',
  fbc: 'fbc.co.zw',
  zimra: 'zimra.co.zw',
  zesa: 'zesa.co.zw',
  steward: 'stewardbank.co.zw',
  innbucks: 'innbucks.co.zw',
  nust: 'nust.ac.zw',
};

// What a scammer is after, per threat class.
const GOAL = {
  phish: 'steal your login details',
  fin: 'get your money or PIN',
  id: 'take over your accounts',
  link: 'infect your phone or steal logins',
  ai: 'rush you into sending money',
};

const THREAT_TYPE = {
  phish: 'Phishing',
  fin: 'Financial Scam',
  id: 'Identity Fraud',
  link: 'Malicious Link',
  ai: 'AI-Enabled Threat',
};

const THREATS = Object.values(THREAT_TYPE).concat(['Benign']);

// Guidance shown to the user, offline, in every supported language.
// Index order matches LANGUAGES below: English, Shona, Ndebele.
const LANGUAGES = ['English', 'Shona', 'Ndebele'];

const ADVICE = {
  phish: [
    'Do not click the link. Open the official website yourself or call the official number.',
    'Usadzvanye link iyi. Vhura website yepamutemo iwe pachako kana kufona nhamba yakasimbiswa.',
    'Ungaceli ikhasi. Vula iwebhusayithi esemthethonweni ngqo bese ucele inombolo epheshe.',
  ],
  fin: [
    'Never share your PIN or money details. Call your provider on its official number.',
    'Usatumire PIN kana mari yako. Fonera kambani yako yemari panhamba yepamutemo.',
    'Ungalokothi wabelane i-PIN noma imali yakho. Shayela umphathi wakho enombolweni epheshe.',
  ],
  id: [
    'Never share passwords, OTPs or ID numbers. Verify the request another way.',
    'Usape password, OTP kana nhamba yeID kumunhu upi zvake. Simbisa nenzira yechipiri.',
    'Ungalokothi wabelane amaphesivhawe, i-OTP noma inombolo ye-ID. Qinisekisa ngendlela ephandle.',
  ],
  link: [
    'Do not open the link or file. Delete it and warn others.',
    'Usavhure link kana file iri. Isa mu-delete uye ambira vamwe.',
    'Ungavuli isixhumi noma ifayili. Yisuse bese wazisa abanye.',
  ],
  ai: [
    'Call the person on a number you already know before doing anything. Agree a family/office code word.',
    'Fonera munhu uyu panhamba yaunoziva usati wabata chinhu. Gadzirai izwi rekuzivana.',
    'Shayela umuntu enombolweni owaziwayo ngaphambi kokwenza into. Ndibanisele igama lokugxina.',
  ],
  ben: [
    'No threat found. Stay alert and use official channels.',
    'Hapana njodzi yakaonekwa. Chengetedzeka uye shandisa nzira dzepamutemo.',
    'Akukho ngozi ebonekayo. Qhubeka uqale futhi usebenzise izindlela ezisemthetho.',
  ],
};

// Set by norm() when leetspeak or slang was detected in the last call.
let disguised = false;

/**
 * Lowercase, strip zero-width characters, undo leetspeak and expand chat
 * shorthand so the rule patterns can match disguised wording.
 */
function norm(s) {
  disguised = false;
  return s
    .normalize('NFKC')
    .replace(/[\u200b-\u200f\u2060\ufeff]/g, '')
    .toLowerCase()
    .split(/(\s+)/)
    .map((k) => {
      if (/^\s*$/.test(k) || /^(https?:|www\.)/.test(k)) return k;
      if (k.length >= 3 && /[a-z]/.test(k) && /[01345@$]/.test(k) && !/\d{2}/.test(k)) {
        k = k.replace(/[01345@$]/g, (c) => LEET[c]);
        disguised = true;
      }
      k = k.replace(/([a-z])\1{2,}/g, '$1$1');
      return k.replace(/^[a-z]+/, (w) => ABBREV[w] || w);
    })
    .join('');
}

/** Levenshtein distance, used to spot misspelled brand lookalikes. */
function lev(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return d[a.length][b.length];
}

/** Inspect every URL in the text. Returns [url, reason, risk weight] tuples. */
function urlCheck(t) {
  const found = [];
  const urls = t.match(
    /\b(?:https?:\/\/|www\.)\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|co\.zw|ac\.zw|xyz|top|click|icu|live|tk|ml|info|site|online|buzz|link)\b\S*/gi
  ) || [];

  urls.forEach((u) => {
    const host = u
      .replace(/^https?:\/\//i, '')
      .replace(/^www\./i, '')
      .split(/[\/?#:]/)[0]
      .toLowerCase()
      .replace(/[.,;)]+$/, '');

    const official = Object.values(BRANDS).some(
      (x) => host === x || host.endsWith('.' + x)
    );
    let flagged = false;

    if (!official) {
      for (const b in BRANDS) {
        if (host.includes(b)) {
          found.push([u, 'Pretends to be ' + b + ' but the real site is ' + BRANDS[b], 3]);
          flagged = true;
          break;
        }
      }
    }

    if (!official && !flagged) {
      for (const label of host.split(/[.-]/)) {
        for (const b in BRANDS) {
          if (label.length >= 4 && b.length >= 4 && label !== b && lev(label, b) <= 1) {
            found.push([u, 'Misspelled lookalike of ' + b, 3]);
            flagged = true;
          }
        }
      }
    }

    if (/\.(xyz|top|click|icu|live|tk|ml|info|site|online|buzz|link)$/.test(host)) {
      found.push([u, 'Unusual web address ending', 1.5]);
    }
    if (/^\d+\.\d+\.\d+\.\d+/.test(host)) {
      found.push([u, 'Uses a raw IP address', 2]);
    }
    if (/^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly)$/.test(host)) {
      found.push([u, 'Shortened link hides the destination', 1.5]);
    }
    if ((host.match(/-/g) || []).length >= 2) {
      found.push([u, 'Many hyphens in the address', 1]);
    }
  });

  return found;
}

/**
 * Score a message.
 * @param {string} txt   raw message text
 * @param {string} ch    channel, e.g. 'SMS' or 'Voice message'
 * @param {boolean} known whether the sender is known to the user
 */
function analyse(txt, ch, known) {
  const n = norm(txt);
  const weights = { phish: 0, fin: 0, id: 0, link: 0, ai: 0 };
  let risk = 0;
  const items = [];

  const add = (m, h, rw) => {
    items.push({ m, h });
    risk += rw;
  };

  for (const [re, classWeights, rw, msg] of RULES) {
    if (msg === 'Creates pressure to act fast') continue;
    const hit = n.match(re);
    if (hit) {
      add(msg, hit[0], rw);
      for (const k in classWeights) weights[k] += classWeights[k];
    }
  }

  // Pressure on its own is weak, so only count it once something else fired.
  const urgency = n.match(/urgent|immediately|\btoday\b|\bnow\b|asap|within \d+ (hours|minutes)/i);
  if (urgency && risk >= 1.5) add('Creates pressure to act fast', urgency[0], 1);

  urlCheck(txt).forEach(([u, m, rw]) => {
    add(m, u, rw);
    // A link that impersonates a known brand is phishing evidence in its own
    // right, not a generic link, so it does not also add to the link class.
    if (rw >= 3) {
      weights.phish += 3;
    } else {
      weights.link += rw >= 1.5 ? 2 : 1;
    }
  });

  if (disguised) add('Disguised spelling: numbers or symbols are hiding words', null, 1.5);

  // Voice and video can be faked with AI, but the channel alone is not proof
  // of an attack: a harmless voice note from family must not read as High. The
  // channel only escalates a message that already has something else wrong.
  if (/voice|video/i.test(ch) && risk > 0) {
    weights.ai += 3;
    add('Voice and video can be faked with AI', null, 3);
  }

  if (known) risk -= 1.5;
  else add('The sender is unknown', null, 0.5);

  if (BENIGN.some((r) => r.test(txt))) risk -= 2;
  risk = Math.max(0, risk);

  const lvl = risk >= 4.5 ? 'High' : risk >= 2 ? 'Medium' : 'Low';
  const top = Object.keys(weights).sort((a, b) => weights[b] - weights[a])[0];
  const threat = lvl === 'Low' || weights[top] === 0 ? 'Benign' : THREAT_TYPE[top];
  const key = threat === 'Benign' ? 'ben' : top;

  return { threat, lvl, risk, items, key, act: ADVICE[key] };
}
