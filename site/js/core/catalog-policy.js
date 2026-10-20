// Platform moderation is mandatory; host owners may impose additional restrictions.
export function catalogAdmissionRefusal(app, version, {forPrivate = false} = {}) {
  if (app?.active !== true) return 'This app is delisted or its catalog status is unavailable.';
  if (!version || version.yanked !== false) return 'This version is yanked or its catalog status is unavailable.';
  if (Number(version.approval) === 2) return 'This version was rejected by the catalog owner.';
  if (Number(version.approval) === 1) return null;
  if (Number(version.approval) === 0 && forPrivate === true) return null;
  return 'This version requires catalog approval; pending versions may only be deployed PRIVATE for testing.';
}
export function catalogStatus(app, version) {
  return [app?.active === false && 'delisted', version?.yanked === true && 'yanked',
    Number(version?.approval) !== 1 && (Number(version?.approval) === 2 ? 'rejected' : 'pending approval')].filter(Boolean).join(', ');
}
export function catalogAdmissionNotice(app, version) {
  if (!catalogStatus(app, version)) return '';
  return catalogAdmissionRefusal(app, version) || '';
}
