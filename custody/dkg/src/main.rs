//! Measured-guest helper. Stdin/stdout are PRIVATE local pipes: round secret
//! packages and round-two messages must never be logged or sent over HTTP.
//! The caller supplies authenticated, broadcast-agreed round-one packages and
//! confidential authenticated round-two packages, as required by ZF FROST.
use frost_secp256k1 as frost;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    error::Error,
    io::{self, Read},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    phase: u8,
    id: u16,
    participants: u16,
    #[serde(default)]
    state: String,
    #[serde(default)]
    round1: BTreeMap<u16, String>,
    #[serde(default)]
    round2: BTreeMap<u16, String>,
}
fn validate_peers<T>(map: &BTreeMap<u16, T>, r: &Request) -> Result<()> {
    if map.len() != usize::from(r.participants - 1)
        || map
            .keys()
            .any(|i| *i == r.id || *i < 1 || *i > r.participants)
    {
        return Err("wrong participant set".into());
    }
    Ok(())
}
fn run(r: Request) -> Result<Value> {
    if !(3..=64).contains(&r.participants) || r.id < 1 || r.id > r.participants {
        return Err("invalid independent committee".into());
    }
    let id = frost::Identifier::try_from(r.id)?;
    let t = (2 * r.participants + 2) / 3;
    if r.phase == 1 {
        if !r.state.is_empty() || !r.round1.is_empty() || !r.round2.is_empty() {
            return Err("unexpected state".into());
        }
        let (secret, public) = frost::keys::dkg::part1(id, r.participants, t, rand::rngs::OsRng)?;
        return Ok(
            json!({"state":hex::encode(secret.serialize()?), "round1":hex::encode(public.serialize()?)}),
        );
    }
    validate_peers(&r.round1, &r)?;
    let mut one = BTreeMap::new();
    for (who, raw) in &r.round1 {
        let p = frost::keys::dkg::round1::Package::deserialize(&hex::decode(raw)?)?;
        if p.commitment().serialize()?.len() != usize::from(t) {
            return Err("wrong threshold".into());
        }
        one.insert(frost::Identifier::try_from(*who)?, p);
    }
    if r.phase == 2 {
        if !r.round2.is_empty() {
            return Err("unexpected round two".into());
        }
        let secret = frost::keys::dkg::round1::SecretPackage::deserialize(&hex::decode(r.state)?)?;
        if *secret.identifier() != id
            || *secret.min_signers() != t
            || *secret.max_signers() != r.participants
        {
            return Err("secret state scope mismatch".into());
        }
        let (secret, outgoing) = frost::keys::dkg::part2(secret, &one)?;
        let mut packages = BTreeMap::new();
        for i in 1..=r.participants {
            if i != r.id {
                packages.insert(
                    i,
                    hex::encode(
                        outgoing
                            .get(&frost::Identifier::try_from(i)?)
                            .ok_or("missing peer")?
                            .serialize()?,
                    ),
                );
            }
        }
        return Ok(json!({"state":hex::encode(secret.serialize()?), "round2":packages}));
    }
    if r.phase != 3 {
        return Err("unknown phase".into());
    }
    validate_peers(&r.round2, &r)?;
    let secret = frost::keys::dkg::round2::SecretPackage::deserialize(&hex::decode(&r.state)?)?;
    if *secret.identifier() != id
        || *secret.min_signers() != t
        || *secret.max_signers() != r.participants
    {
        return Err("secret state scope mismatch".into());
    }
    let mut two = BTreeMap::new();
    for (who, raw) in &r.round2 {
        two.insert(
            frost::Identifier::try_from(*who)?,
            frost::keys::dkg::round2::Package::deserialize(&hex::decode(raw)?)?,
        );
    }
    let (key, public) = frost::keys::dkg::part3(&secret, &one, &two)?;
    // Public coefficient vectors let the existing custody client derive the
    // aggregate Feldman commitments. It must check them against Y/share below.
    let mut coefficients = vec![hex::encode(secret.commitment().serialize_whole()?)];
    for p in one.values() {
        coefficients.push(hex::encode(p.commitment().serialize_whole()?));
    }
    Ok(json!({"share":hex::encode(key.signing_share().serialize()),
        "verifyingShare":hex::encode(key.verifying_share().serialize()?),
        "Y":hex::encode(public.verifying_key().serialize()?), "coefficients":coefficients}))
}
fn main() {
    let result = (|| -> Result<Value> {
        let mut input = Vec::new();
        io::stdin().take(1_048_577).read_to_end(&mut input)?;
        if input.len() > 1_048_576 {
            return Err("oversized request".into());
        }
        run(serde_json::from_slice(&input)?)
    })();
    match result {
        Ok(v) => println!("{}", v),
        Err(_) => {
            eprintln!("custody DKG request refused");
            std::process::exit(1);
        }
    }
}
