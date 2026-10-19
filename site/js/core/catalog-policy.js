// Catalog status is a recommendation. Each host's owning wallet controls admission.
export function catalogStatus(app, version) {
  return [app?.active === false && 'delisted', version?.yanked === true && 'yanked',
    Number(version?.approval) !== 1 && (Number(version?.approval) === 2 ? 'rejected' : 'pending approval')].filter(Boolean).join(', ');
}
export function catalogAdmissionNotice(app, version) {
  const status = catalogStatus(app, version);
  return status ? `Catalog status: ${status}. Each host decides whether to run this release; a host may decline it.` : '';
}
