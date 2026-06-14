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

    document.querySelectorAll('.plan').forEach((el) =>
      el.classList.toggle('selected', el.dataset.plan === plan));

    $('pricePremium').textContent = cycle === 'annual' ? money(PLANS.premium.annual) : money(PLANS.premium.monthly);
    $('premiumPer').textContent = cycle === 'annual' ? '/yr' : '/mo';

    $('sumPlan').textContent = p.name;
    $('sumCycle').textContent = cycle === 'annual' ? 'Annual' : 'Monthly';
    $('sumSubtotal').textContent = money(price);
    $('sumTotal').textContent = money(price);

    if (isFree) {
      $('sumNote').textContent = 'Free forever. Cancel anytime.';
    } else if (cycle === 'annual') {
      $('sumNote').textContent = `Billed ${money(price)} yearly (≈ ${money(price / 12)}/mo). Cancel anytime.`;
    } else {
      $('sumNote').textContent = `Renews monthly at ${money(price)}. Cancel anytime.`;
    }

    $('payBtnLabel').textContent = 'Continue';
  }

  /* --------------------------- Interactions -------------------------- */
  function selectPlan(id) { plan = id; render(); }
  function setCycle(c) {
    cycle = c;
    document.querySelectorAll('#billing button').forEach((b) =>
      b.classList.toggle('active', b.dataset.cycle === c));
    render();
  }

  function onContinue() {
    $('payBtn').hidden = true;
    $('paySuccess').hidden = false;
    if (plan === 'free') {
      $('successTitle').textContent = 'Account created';
      $('successText').textContent = 'Your free Delock account is ready.';
    } else {
      $('successTitle').textContent = "You're all set";
      $('successText').textContent = `Welcome to Delock ${PLANS[plan].name} (${cycle === 'annual' ? 'annual' : 'monthly'}).`;
    }
    $('paySuccess').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  /* ------------------------------ Init ------------------------------- */
  function init() {
    const params = new URLSearchParams(location.search);
    const wanted = (params.get('plan') || '').toLowerCase();
    if (PLANS[wanted]) plan = wanted;

    document.querySelectorAll('.plan').forEach((el) =>
      el.addEventListener('click', () => selectPlan(el.dataset.plan)));
    document.querySelectorAll('#billing button').forEach((b) =>
      b.addEventListener('click', () => setCycle(b.dataset.cycle)));
    $('payBtn').addEventListener('click', onContinue);

    render();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
