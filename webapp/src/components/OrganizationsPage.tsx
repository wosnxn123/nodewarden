import { useEffect, useState } from 'preact/hooks';
import { decryptBw } from '@/lib/crypto';
import { getOwnerKeyParts } from '@/lib/organization-crypto';
import { t } from '@/lib/i18n';
import type { AuthedFetch } from '@/lib/api/shared';
import {
  acceptOrganizationInvitation,
  confirmOrganizationMember,
  createOrganization,
  createOrganizationCollection,
  deleteOrganizationCollection,
  inviteOrganizationMember,
  listOrganizationCollections,
  listOrganizationInvitations,
  listOrganizationMembers,
  listOrganizations,
  renameOrganizationCollection,
  restoreOrganizationMember,
  revokeOrganizationMember,
  shareCipher,
  updateCipherCollections,
  updateOrganizationMember,
} from '@/lib/api/organizations';
import type {
  Cipher,
  Organization,
  OrganizationCollection,
  OrganizationInvitation,
  OrganizationMember,
  Profile,
  SessionState,
} from '@/lib/types';

interface Props {
  session: SessionState;
  profile: Profile;
  authedFetch: AuthedFetch;
  ciphers: Cipher[];
  onRefresh: () => Promise<void>;
  onNotify: (type: 'success' | 'error' | 'warning', message: string) => void;
}

function MemberEditor(props: {
  member: OrganizationMember;
  collections: OrganizationCollection[];
  disabled: boolean;
  onSave: (member: OrganizationMember) => void;
}) {
  const [draft, setDraft] = useState(props.member);
  return (
    <form
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        props.onSave(draft);
      }}
    >
      <fieldset disabled={props.disabled} className="stack">
        <label>
          {t('txt_role')}
          <select
            className="input"
            value={draft.type}
            onChange={(event) =>
              setDraft({ ...draft, type: Number(event.currentTarget.value) })
            }
          >
            <option value={0}>{t('org_owner')}</option>
            <option value={1}>{t('txt_role_admin')}</option>
            <option value={2}>{t('txt_role_user')}</option>
            <option value={3}>{t('org_manager')}</option>
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={draft.accessAll}
            onChange={(event) =>
              setDraft({ ...draft, accessAll: event.currentTarget.checked })
            }
          />{' '}
          {t('org_access_all')}
        </label>
        {!draft.accessAll &&
          props.collections.map((collection) => {
            const assignment = draft.collections?.find(
              (entry) => entry.id === collection.id
            );
            const change = (patch: Partial<NonNullable<typeof assignment>>) =>
              setDraft({
                ...draft,
                collections: (draft.collections || []).map((entry) =>
                  entry.id === collection.id ? { ...entry, ...patch } : entry
                ),
              });
            return (
              <div className="stack" key={collection.id}>
                <label>
                  <input
                    type="checkbox"
                    checked={!!assignment}
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        collections: event.currentTarget.checked
                          ? [
                              ...(draft.collections || []),
                              {
                                id: collection.id,
                                readOnly: false,
                                hidePasswords: false,
                                manage: false,
                              },
                            ]
                          : (draft.collections || []).filter(
                              (entry) => entry.id !== collection.id
                            ),
                      })
                    }
                  />{' '}
                  {collection.decName || collection.id}
                </label>
                {assignment && (
                  <div className="row flex-wrap">
                    <label>
                      <input
                        type="checkbox"
                        checked={assignment.readOnly}
                        onChange={(event) =>
                          change({ readOnly: event.currentTarget.checked })
                        }
                      />{' '}
                      {t('org_read_only')}
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={assignment.hidePasswords}
                        onChange={(event) =>
                          change({ hidePasswords: event.currentTarget.checked })
                        }
                      />{' '}
                      {t('org_hide_passwords')}
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={!!assignment.manage}
                        onChange={(event) =>
                          change({ manage: event.currentTarget.checked })
                        }
                      />{' '}
                      {t('org_manage_collection')}
                    </label>
                  </div>
                )}
              </div>
            );
          })}
        <button type="submit" className="btn btn-secondary">
          {t('txt_save')}
        </button>
      </fieldset>
    </form>
  );
}

export default function OrganizationsPage(props: Props) {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [collections, setCollections] = useState<OrganizationCollection[]>([]);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [busy, setBusy] = useState(false);
  const [detailsRevision, setDetailsRevision] = useState(0);
  const [error, setError] = useState('');
  const [orgName, setOrgName] = useState('');
  const [billingEmail, setBillingEmail] = useState(props.profile.email);
  const [initialCollection, setInitialCollection] = useState('');
  const [collectionName, setCollectionName] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteType, setInviteType] = useState(2);
  const [accessAll, setAccessAll] = useState(false);
  const [inviteCollections, setInviteCollections] = useState<string[]>([]);
  const [shareItemId, setShareItemId] = useState('');
  const [shareCollections, setShareCollections] = useState<string[]>([]);
  const selected = organizations.find((org) => org.id === selectedId);
  const canAdmin = !!selected && (selected.type === 0 || selected.type === 1);
  const hasKey = !!props.session.organizationKeys?.[selectedId];
  const online = !!props.session.accessToken;
  const disabled = busy || !online;
  const statusName = (status: number) =>
    t(
      status === -1
        ? 'org_revoked'
        : status === 0
          ? 'org_invited'
          : status === 1
            ? 'org_accepted'
            : 'org_confirmed'
    );

  async function refresh() {
    const [orgs, pending] = await Promise.all([
      listOrganizations(props.authedFetch),
      listOrganizationInvitations(props.authedFetch),
    ]);
    setOrganizations(orgs);
    setInvitations(pending);
    setSelectedId((current) =>
      orgs.some((org) => org.id === current) ? current : orgs[0]?.id || ''
    );
  }
  async function loadDetails(org: Organization) {
    const [rawCollections, orgMembers] = await Promise.all([
      listOrganizationCollections(props.authedFetch, org.id),
      org.type <= 1
        ? listOrganizationMembers(props.authedFetch, org.id)
        : Promise.resolve([]),
    ]);
    const decoded = await Promise.all(
      rawCollections.map(async (collection) => {
        try {
          const owner = getOwnerKeyParts(
            { organizationId: org.id },
            props.session
          );
          return {
            ...collection,
            decName: new TextDecoder().decode(
              await decryptBw(collection.name, owner.enc, owner.mac)
            ),
          };
        } catch {
          return { ...collection, decName: '' };
        }
      })
    );
    return { decoded, orgMembers };
  }
  async function run(action: () => Promise<unknown>) {
    if (disabled) return;
    setBusy(true);
    setError('');
    try {
      await action();
      await props.onRefresh();
      await refresh();
      // The effect below loads the CURRENT selection and cancels stale work.
      // Never repopulate details from the organization captured before await.
      setDetailsRevision((revision) => revision + 1);
      props.onNotify('success', t('org_updated'));
    } catch (reason) {
      const message =
        reason instanceof Error ? reason.message : t('org_operation_failed');
      setError(message);
      props.onNotify('error', message);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    void refresh().catch((reason) =>
      setError(
        reason instanceof Error ? reason.message : t('org_operation_failed')
      )
    );
  }, []);
  useEffect(() => {
    let active = true;
    setCollections([]);
    setMembers([]);
    setShareCollections([]);
    setInviteCollections([]);
    if (selected)
      void loadDetails(selected)
        .then((details) => {
          if (active) {
            setCollections(details.decoded);
            setMembers(details.orgMembers);
          }
        })
        .catch((reason) => {
          if (active)
            setError(
              reason instanceof Error
                ? reason.message
                : t('org_operation_failed')
            );
        });
    return () => {
      active = false;
    };
  }, [
    selectedId,
    selected?.type,
    props.session.organizationKeys,
    detailsRevision,
  ]);
  function toggle(ids: string[], id: string, checked: boolean) {
    return checked ? [...ids, id] : ids.filter((value) => value !== id);
  }

  return (
    <div className="stack" aria-busy={busy}>
      <div className="row justify-between flex-wrap">
        <h1>{t('org_title')}</h1>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={disabled}
          onClick={() => void run(async () => {})}
        >
          {t('txt_refresh')}
        </button>
      </div>
      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
      {!online && <p role="status">{t('txt_offline_vault_readonly')}</p>}
      {invitations.length > 0 && (
        <section className="card stack">
          <h2>{t('txt_invites')}</h2>
          {invitations.map((invitation) => (
            <div key={invitation.id} className="row justify-between flex-wrap">
              <span>
                {invitation.organizationName} — {statusName(invitation.status)}
              </span>
              {invitation.status === 0 && (
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={disabled}
                  onClick={() =>
                    void run(() =>
                      acceptOrganizationInvitation(
                        props.authedFetch,
                        invitation
                      )
                    )
                  }
                >
                  {t('org_accept')}
                </button>
              )}
            </div>
          ))}
        </section>
      )}
      <details className="card stack" open={!organizations.length}>
        <summary>{t('org_create')}</summary>
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void run(async () => {
              const created = await createOrganization(
                props.authedFetch,
                props.profile,
                orgName.trim(),
                billingEmail.trim(),
                initialCollection.trim()
              );
              setSelectedId(created.id);
              setOrgName('');
            });
          }}
        >
          <fieldset
            disabled={disabled || !props.profile.publicKey}
            className="stack"
          >
            <label>
              {t('txt_name')}
              <input
                className="input"
                required
                maxLength={200}
                value={orgName}
                onInput={(event) => setOrgName(event.currentTarget.value)}
              />
            </label>
            <label>
              {t('org_billing_email')}
              <input
                className="input"
                type="email"
                required
                value={billingEmail}
                onInput={(event) => setBillingEmail(event.currentTarget.value)}
              />
            </label>
            <label>
              {t('org_initial_collection')}
              <input
                className="input"
                required
                maxLength={200}
                value={initialCollection}
                onInput={(event) =>
                  setInitialCollection(event.currentTarget.value)
                }
              />
            </label>
            <button type="submit" className="btn btn-primary">
              {t('org_create')}
            </button>
          </fieldset>
        </form>
      </details>
      {!organizations.length ? (
        <p>{t('org_empty')}</p>
      ) : (
        <label>
          {t('org_title')}
          <select
            className="input"
            value={selectedId}
            onChange={(event) => setSelectedId(event.currentTarget.value)}
          >
            {organizations.map((org) => (
              <option key={org.id} value={org.id}>
                {org.name}
              </option>
            ))}
          </select>
        </label>
      )}
      {selected && (
        <>
          {!hasKey && <p role="status">{t('org_key_unavailable')}</p>}
          <section className="card stack">
            <h2>{t('org_collections')}</h2>
            {collections.map((collection) => (
              <div
                key={collection.id}
                className="row justify-between flex-wrap"
              >
                <span>
                  {collection.decName || collection.id}
                  {collection.readOnly ? ` · ${t('org_read_only')}` : ''}
                </span>
                {canAdmin && hasKey && (
                  <details>
                    <summary>{t('txt_edit')}</summary>
                    <form
                      className="row flex-wrap"
                      onSubmit={(event) => {
                        event.preventDefault();
                        const form = new FormData(event.currentTarget);
                        void run(() =>
                          renameOrganizationCollection(
                            props.authedFetch,
                            props.session,
                            collection,
                            String(form.get('name') || '').trim()
                          )
                        );
                      }}
                    >
                      <input
                        className="input"
                        name="name"
                        required
                        aria-label={t('txt_name')}
                        defaultValue={collection.decName}
                      />
                      <button className="btn btn-secondary" disabled={disabled}>
                        {t('txt_save')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={disabled}
                        onClick={() => {
                          if (window.confirm(t('org_delete_collection')))
                            void run(() =>
                              deleteOrganizationCollection(
                                props.authedFetch,
                                selectedId,
                                collection.id
                              )
                            );
                        }}
                      >
                        {t('txt_delete')}
                      </button>
                    </form>
                  </details>
                )}
              </div>
            ))}
            {canAdmin && (
              <form
                className="row flex-wrap"
                onSubmit={(event) => {
                  event.preventDefault();
                  void run(async () => {
                    await createOrganizationCollection(
                      props.authedFetch,
                      props.session,
                      selectedId,
                      collectionName.trim()
                    );
                    setCollectionName('');
                  });
                }}
              >
                <label>
                  {t('txt_name')}
                  <input
                    className="input"
                    required
                    value={collectionName}
                    onInput={(event) =>
                      setCollectionName(event.currentTarget.value)
                    }
                  />
                </label>
                <button
                  className="btn btn-primary"
                  disabled={disabled || !hasKey}
                >
                  {t('txt_create')}
                </button>
              </form>
            )}
          </section>
          {canAdmin && (
            <section className="card stack">
              <h2>{t('org_members')}</h2>
              {members.map((member) => (
                <div key={`${member.id}:${member.status}`} className="stack">
                  <div className="row justify-between flex-wrap">
                    <span>
                      {member.email} — {statusName(member.status)}
                    </span>
                    <div className="row flex-wrap">
                      {member.status === 1 && (
                        <button
                          type="button"
                          className="btn btn-primary"
                          disabled={disabled || !hasKey}
                          onClick={() =>
                            void run(() =>
                              confirmOrganizationMember(
                                props.authedFetch,
                                props.session,
                                selectedId,
                                member
                              )
                            )
                          }
                        >
                          {t('txt_confirm')}
                        </button>
                      )}
                      {member.status !== -1 &&
                        member.userId !== props.profile.id && (
                          <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={disabled}
                            onClick={() =>
                              void run(() =>
                                revokeOrganizationMember(
                                  props.authedFetch,
                                  selectedId,
                                  member.id
                                )
                              )
                            }
                          >
                            {t('txt_revoke')}
                          </button>
                        )}
                      {member.status === -1 && (
                        <button
                          type="button"
                          className="btn btn-secondary"
                          disabled={disabled}
                          onClick={() =>
                            void run(() =>
                              restoreOrganizationMember(
                                props.authedFetch,
                                selectedId,
                                member.id
                              )
                            )
                          }
                        >
                          {t('txt_restore')}
                        </button>
                      )}
                    </div>
                  </div>
                  <details>
                    <summary>{t('txt_edit')}</summary>
                    <MemberEditor
                      key={JSON.stringify(member)}
                      member={member}
                      collections={collections}
                      disabled={disabled}
                      onSave={(draft) =>
                        void run(() =>
                          updateOrganizationMember(
                            props.authedFetch,
                            selectedId,
                            draft
                          )
                        )
                      }
                    />
                  </details>
                </div>
              ))}
              <h3>{t('org_invite')}</h3>
              <p className="muted">{t('org_invite_notice')}</p>
              <form
                className="stack"
                onSubmit={(event) => {
                  event.preventDefault();
                  void run(async () => {
                    await inviteOrganizationMember(
                      props.authedFetch,
                      selectedId,
                      inviteEmail.trim(),
                      inviteType,
                      accessAll,
                      inviteCollections
                    );
                    setInviteEmail('');
                  });
                }}
              >
                <fieldset className="stack" disabled={disabled}>
                  <label>
                    {t('txt_email')}
                    <input
                      className="input"
                      type="email"
                      required
                      value={inviteEmail}
                      onInput={(event) =>
                        setInviteEmail(event.currentTarget.value)
                      }
                    />
                  </label>
                  <label>
                    {t('txt_role')}
                    <select
                      className="input"
                      value={inviteType}
                      onChange={(event) =>
                        setInviteType(Number(event.currentTarget.value))
                      }
                    >
                      <option value={2}>{t('txt_role_user')}</option>
                      <option value={1}>{t('txt_role_admin')}</option>
                      <option value={3}>{t('org_manager')}</option>
                    </select>
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={accessAll}
                      onChange={(event) =>
                        setAccessAll(event.currentTarget.checked)
                      }
                    />{' '}
                    {t('org_access_all')}
                  </label>
                  {!accessAll &&
                    collections.map((collection) => (
                      <label key={collection.id}>
                        <input
                          type="checkbox"
                          checked={inviteCollections.includes(collection.id)}
                          onChange={(event) =>
                            setInviteCollections(
                              toggle(
                                inviteCollections,
                                collection.id,
                                event.currentTarget.checked
                              )
                            )
                          }
                        />{' '}
                        {collection.decName || collection.id}
                      </label>
                    ))}
                  <button className="btn btn-primary">{t('org_invite')}</button>
                </fieldset>
              </form>
            </section>
          )}
          {hasKey && (
            <section className="card stack">
              <h2>{t('org_share')}</h2>
              <p>{t('org_share_notice')}</p>
              <form
                className="stack"
                onSubmit={(event) => {
                  event.preventDefault();
                  const cipher = props.ciphers.find(
                    (item) => item.id === shareItemId
                  );
                  if (!cipher) return;
                  if (!shareCollections.length) {
                    setError(t('org_select_collection'));
                    return;
                  }
                  void run(async () => {
                    if (cipher.organizationId)
                      await updateCipherCollections(
                        props.authedFetch,
                        cipher,
                        shareCollections
                      );
                    else
                      await shareCipher(
                        props.authedFetch,
                        props.session,
                        cipher,
                        selectedId,
                        shareCollections
                      );
                    setShareItemId('');
                  });
                }}
              >
                <fieldset disabled={disabled} className="stack">
                  <label>
                    {t('org_select_item')}
                    <select
                      className="input"
                      required
                      value={shareItemId}
                      onChange={(event) => {
                        const id = event.currentTarget.value;
                        setShareItemId(id);
                        setShareCollections(
                          props.ciphers.find((cipher) => cipher.id === id)
                            ?.collectionIds || []
                        );
                      }}
                    >
                      <option value="">{t('org_select_item')}</option>
                      {props.ciphers
                        .filter(
                          (cipher) =>
                            (!cipher.organizationId ||
                              cipher.organizationId === selectedId) &&
                            !cipher.deletedDate &&
                            !cipher.decryptionUnavailable &&
                            cipher.edit !== false
                        )
                        .map((cipher) => (
                          <option key={cipher.id} value={cipher.id}>
                            {cipher.decName || cipher.id}
                          </option>
                        ))}
                    </select>
                  </label>
                  {collections
                    .filter((collection) => !collection.readOnly || canAdmin)
                    .map((collection) => (
                      <label key={collection.id}>
                        <input
                          type="checkbox"
                          checked={shareCollections.includes(collection.id)}
                          onChange={(event) =>
                            setShareCollections(
                              toggle(
                                shareCollections,
                                collection.id,
                                event.currentTarget.checked
                              )
                            )
                          }
                        />{' '}
                        {collection.decName || collection.id}
                      </label>
                    ))}
                  <button
                    className="btn btn-primary"
                    disabled={!shareItemId || !shareCollections.length}
                  >
                    {props.ciphers.find((cipher) => cipher.id === shareItemId)
                      ?.organizationId
                      ? t('txt_save')
                      : t('org_share')}
                  </button>
                </fieldset>
              </form>
            </section>
          )}
        </>
      )}
    </div>
  );
}
