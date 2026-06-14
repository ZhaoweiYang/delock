/* Delock — membership / checkout page */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);

  const PLANS = {
    free:    { name: 'Free',    monthly: 0,    annual: 0 },
    premium: { name: 'Premium', monthly: 19.9, annual: 191 }
  };

  let plan = 'premium';
  let cycle = 'monthly';

  const money = (n) => '$' + n.toFixed(2);

  /* ------------------------------ Render ----------------------------- */
  function render() {
    const p = PLANS[plan];
    const price = cycle === 'annual' ? p.annual : p.monthly;
    const isFree = plan === 'free';

    // plan cards selected state
    document.querySelectorAll('.plan').forEach((el) =>
      el.classList.toggle('selected', el.dataset.plan === plan));

    // premium price label reflects cycle
    $('pricePremium').textContent = cycle === 'annual' ? money(PLANS.premium.annual) : money(PLANS.premium.monthly);
    $('premiumPer').textContent = cycle === 'annual' ? '/yr' : '/mo';

    // summary
    $('sumPlan').textContent = p.name;
    $('sumCycle').textContent = cycle === 'annual' ? 'Annual' : 'Monthly';
    $('sumSubtotal').textContent = money(price);
    $('sumTotal').textContent = money(price);

    if (isFree) {
      $('sumNote').textContent = 'Free forever. No card required.';
    } else if (cycle === 'annual') {
      $('sumNote').textContent = `Billed ${money(price)} yearly (≈ ${money(price / 12)}/mo). Cancel anytime.`;
    } else {
      $('sumNote').textContent = `Renews monthly at ${money(price)}. Cancel anytime.`;
    }

    // payment fields + button label
    $('cardFields').hidden = isFree;
    $('payBtnLabel').textContent = isFree ? 'Create free account' : `Pay ${money(price)}`;
  }

  /* --------------------------- Interactions -------------------------- */
  function selectPlan(id) { plan = id; render(); }
  function setCycle(c) {
    cycle = c;
    document.querySelectorAll('#billing button').forEach((b) =>
      b.classList.toggle('active', b.dataset.cycle === c));
    render();
  }

  /* ------------------------ Input formatting ------------------------- */
  function groupCard(v) { return v.replace(/\D/g, '').slice(0, 16).replace(/(.{4})/g, '$1 ').trim(); }
  function fmtExp(v) {
    const d = v.replace(/\D/g, '').slice(0, 4);
    return d.length >= 3 ? d.slice(0, 2) + ' / ' + d.slice(2) : d;
  }

  function init() {
    // preselect plan from ?plan=
    const params = new URLSearchParams(location.search);
    const wanted = (params.get('plan') || '').toLowerCase();
    if (PLANS[wanted]) plan = wanted;

    document.querySelectorAll('.plan').forEach((el) =>
      el.addEventListener('click', () => selectPlan(el.dataset.plan)));
    document.querySelectorAll('#billing button').forEach((b) =>
      b.addEventListener('click', () => setCycle(b.dataset.cycle)));

    $('card').addEventListener('input', (e) => { e.target.value = groupCard(e.target.value); });
    $('exp').addEventListener('input', (e) => { e.target.value = fmtExp(e.target.value); });
    $('cvc').addEventListener('input', (e) => { e.target.value = e.target.value.replace(/\D/g, '').slice(0, 4); });

    $('payForm').addEventListener('submit', onSubmit);

    render();
  }

  function flagInvalid(el) {
    el.closest('.pay-input').style.borderColor = '#ff5a3c';
    el.focus();
    setTimeout(() => { el.closest('.pay-input').style.borderColor = ''; }, 1600);
  }

  function onSubmit(e) {
    e.preventDefault();
    const email = $('email').value.trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { flagInvalid($('email')); return; }

    if (plan !== 'free') {
      const digits = $('card').value.replace(/\D/g, '');
      if (digits.length < 15) { flagInvalid($('card')); return; }
      if ($('exp').value.replace(/\D/g, '').length < 4) { flagInvalid($('exp')); return; }
      if ($('cvc').value.length < 3) { flagInvalid($('cvc')); return; }
      if (!$('name').value.trim()) { flagInvalid($('name')); return; }
    }

    // demo success
    $('payForm').hidden = true;
    const ok = $('paySuccess');
    ok.hidden = false;
    if (plan === 'free') {
      $('successTitle').textContent = 'Account created';
      $('successText').textContent = 'Your free Delock account is ready.';
    } else {
      $('successTitle').textContent = 'Payment successful';
      $('successText').textContent = `Welcome to Delock ${PLANS[plan].name}. A receipt was sent to ${email}.`;
    }
    window.scrollTo({ top: document.querySelector('.pay-checkout').offsetTop - 80, behavior: 'smooth' });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
