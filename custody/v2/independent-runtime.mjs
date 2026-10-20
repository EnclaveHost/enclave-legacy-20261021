// The measured custodian's /v2/custody/independent-genesis handler (daemon.mjs), kept here so it runs without a chip.
// It decides which sealed plan this identity serves, may abandon an UNFINISHED session for a fully permitted
// replacement (one founder refusing must not strand the others' identities), activates (submits only when the committee
// is absent, then adopts from the chain), and erases the DKG copy of the share once the member engine holds it.
import * as D from './digests.mjs';
import { createIndependentGenesis, independentSession } from './independent-genesis.mjs';

// Abandoned sessions are tombstones, never forgotten: at the limit this identity refuses further replans (fail closed)
// and its operator starts a fresh custodian identity, rather than letting an old fully-permitted plan come back.
export const MAX_ABANDONED = 16;
const SIG = /^0x[0-9a-fA-F]{130}$/;

// state: the daemon's sealed state object (independentPlan, independentDkg, abandonedSessions); persist() seals it.
export function createIndependentService({ policy, member, chain, identity, encPrivateKey, invoke, state, persist, fetchJson, submit, log = () => {} }) {
  if (!policy) return Object.assign(async () => { throw Error('independent genesis not enabled in this measured image'); }, { adoptIfCreated: async () => null });
  const verify = plan => member.verifyGenesisRoster(plan, policy);
  const engineFor = plan => createIndependentGenesis({ plan, identity, encPrivateKey, invoke, verifyRoster: verify,
    store: { load: () => state.independentDkg, save: async s => { state.independentDkg = s; await persist(); } } });
  let dkg = null;

  async function replan(plan) {
    let next;
    try { next = independentSession(plan); } catch { throw Error('invalid independent genesis plan'); }
    const sealed = independentSession(state.independentPlan);
    if (next === sealed) return;
    // Only a session that produced no share and no founder signature, only for a plan every founder's operator (and
    // owner, by policy) permitted, and never back to an abandoned session: a replayed old plan cannot flip-flop it.
    if ((state.independentDkg?.phase || 0) >= 3) throw Error('a finished DKG session is bound to this identity');
    const abandoned = Array.isArray(state.abandonedSessions) ? state.abandonedSessions : [];
    if (abandoned.includes(next)) throw Error('that DKG session was abandoned');
    if (abandoned.length >= MAX_ABANDONED) throw Error('replan limit reached: start a fresh custodian identity for another plan');
    if (await verify(plan) !== true) throw Error('replacement roster not verified');
    state.abandonedSessions = [...abandoned, sealed];
    state.independentDkg = null; state.independentPlan = plan; dkg = null;
    await persist();
    log('[independent] abandoned an unfinished DKG session for a fully permitted replacement plan');
  }
  async function engine(body) {
    if (state.independentPlan && body.action === 'start' && body.plan && typeof body.plan === 'object') await replan(body.plan);
    if (!dkg) {
      const plan = state.independentPlan || body.plan;
      if (!plan || await verify(plan) !== true) throw Error('independent roster not verified');
      const candidate = engineFor(plan);
      if (!state.independentPlan) { state.independentPlan = plan; await persist(); }
      dkg = candidate;
    }
    return dkg;
  }

  async function activate(body) {
    const s = state.independentDkg, plan = state.independentPlan;
    if (s?.phase !== 3 || !s.result) throw Error('independent DKG has not finished');
    dkg ||= engineFor(plan);
    if (member.committees().includes(s.committeeId)) {
      if (!s.adopted) await dkg.forgetShare();
      return { committeeId: s.committeeId, adopted: true };
    }
    if (s.adopted) throw Error('the genesis share was already handed to the member engine');
    if (!Array.isArray(body.results) || body.results.length !== plan.machines.length) throw Error('all founder signatures required');
    const results = [...body.results].sort((a, b) => a.id - b.id);
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.id !== i + 1 || r.committeeId !== s.committeeId || r.commitments !== s.commitments ||
          await D.recoverDigest(D.independentGenesisDigest({ ...plan, committeeId: r.committeeId, commitments: r.commitments }), r.signature) !== plan.machines[i].identity.toLowerCase())
        throw Error('founder agreement mismatch');
    }
    const current = await chain.readCommittee({ committeeId: s.committeeId });
    if (!current.committee) {
      // The vault re-checks every host binding, accepted owner and founder signature; this host only pays gas. Host
      // signatures may come with the request (any coordinator can gather them) so one offline peer cannot block it.
      let hostSigs = body.hostSigs;
      if (!Array.isArray(hostSigs) || hostSigs.length !== plan.machines.length || !hostSigs.every(x => SIG.test(String(x)))) {
        hostSigs = [];
        for (const m of plan.machines) { const info = await fetchJson(`${m.endpoint}/v2/custody/info`); hostSigs.push(info.hostSig); }
      }
      await submit('createIndependentCommittee', [plan.salt, plan.machines, s.commitments, plan.codeSet, results.map(r => r.signature), hostSigs]);
    }
    // Adoption trusts only the agreed chain: the committee's commitments and this machine's seat. No peer must answer.
    const adopted = await member.adoptIndependentGenesis(s);
    await persist();                 // the member's share is durable before the genesis copy is erased
    await dkg.forgetShare();
    return adopted;
  }

  // A founder that was down during activation adopts by itself once the committee is on the agreed chain: no
  // coordinator re-run, which would need every founder reachable again.
  async function adoptIfCreated() {
    const s = state.independentDkg;
    if (s?.phase !== 3 || !s.result || s.adopted || member.committees().includes(s.committeeId)) return null;
    if (!(await chain.readCommittee({ committeeId: s.committeeId })).committee) return null;
    dkg ||= engineFor(state.independentPlan);
    const adopted = await member.adoptIndependentGenesis(s);
    await persist();
    await dkg.forgetShare();
    log(`[independent] adopted committee ${s.committeeId} from the chain`);
    return adopted;
  }

  let tail = Promise.resolve();
  async function run(body) {
    if (!body || typeof body !== 'object') throw Error('unknown independent genesis action');
    if (body.action === 'activate') return activate(body);
    const e = await engine(body);
    if (body.action === 'start') return e.start();
    if (body.action === 'agree') return e.agree(body.round1);
    if (body.action === 'exchange') return e.exchange(body.acks);
    if (body.action === 'finish') return e.finish(body.messages);
    throw Error('unknown independent genesis action');
  }
  const serial = fn => (...a) => { const next = tail.then(() => fn(...a)); tail = next.catch(() => {}); return next; };
  const handler = serial(run);
  handler.adoptIfCreated = serial(adoptIfCreated);
  return handler;
}
