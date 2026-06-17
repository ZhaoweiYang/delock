/* Delock — membership / checkout page */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);

  const PLANS = {
    basic:   { name: 'Basic',   monthly: 1,    annual: 9.6 },
    premium: { name: 'Premium', monthly: 19.9, annual: 191 }
  };

  let plan = 'premium';
  let cycle = 'monthly';
  const money = (n) => '$' + n.toFixed(2);
  const priceOf = (id) => cycle === 'annual' ? PLANS[id].annual : PLANS[id].monthly;

  /* ------------------------------ Render ----------------------------- */
  function render() {
    const price = priceOf(plan);

    document.querySelectorAll('.plan').forEach((el) =>
      el.classList.toggle('selected', el.dataset.plan === plan));

    // card prices reflect the billing cycle
    $('priceBasic').textContent = money(priceOf('basic'));
    $('basicPer').textContent = cycle === 'annual' ? '/yr' : '/mo';
    $('pricePremium').textContent = money(priceOf('premium'));
    $('premiumPer').textContent = cycle === 'annual' ? '/yr' : '/mo';

    $('sumPlan').textContent = PLANS[plan].name;
    $('sumCycle').textContent = cycle === 'annual' ? 'Annual' : 'Monthly';
    $('sumSubtotal').textContent = money(price);
    $('sumTotal').textContent = money(price);

    if (cycle === 'annual') {
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
    location.href = 'success.html?plan=' + plan + '&cycle=' + cycle;
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

    // exit-intent: offer a $0.01 3-day trial when leaving via the back button
    const back = document.querySelector('.pay-back');
    const trial = $('trialModal');
    const hideTrial = () => { trial.hidden = true; };
    if (back) back.addEventListener('click', (e) => { e.preventDefault(); trial.hidden = false; });
    $('trialClose').addEventListener('click', hideTrial);
    $('trialBackdrop').addEventListener('click', hideTrial);
    $('trialLeave').addEventListener('click', () => { location.href = (back && back.getAttribute('href')) || 'index.html'; });
    $('trialAccept').addEventListener('click', () => { location.href = 'success.html?trial=1'; });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !trial.hidden) hideTrial(); });

    render();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
