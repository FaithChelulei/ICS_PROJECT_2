import { useState } from 'react';

// KDPA s.29 (duty to notify): tell people how their data is used BEFORE it
// is collected. Kept to one plain sentence plus a tick box; the fuller
// explanation is one click away. Accepting is required, and the version
// accepted is stored by the backend (services/privacyNotice.js -- keep the
// two versions in step when the text changes).
export const PRIVACY_NOTICE_VERSION = '2026-11';

const NOTICES = {
  account: {
    summary: 'Your name and email are only used to run and protect your account, and you keep rights over your data.',
    details: [
      'An administrator checks every request before an account is created.',
      'Activity is recorded to help keep children’s information safe.',
      // KDPA s.35: say that activity is checked automatically and what that can do.
      'Your activity is also checked automatically for unusual patterns. If something looks unusual you may be signed out and emailed to confirm it was you. A person reviews every such alert, and nothing lasting happens to your account without one.',
      'Your details are never sold or shared.',
    ],
    // KDPA s.26: the data subject's rights, agreed once when the account is requested.
    rightsTitle: 'Your rights',
    rights: [
      'Correct a child’s details at any time.',
      'Parents decide which educators may see a child’s records, and can take that back (Who Can See My Child).',
      'Withdraw consent for records, or archive a child’s profile, whenever you choose.',
    ],
  },
  child: {
    summary: 'This child’s details are kept private and secure. Only you can see or change them.',
    details: [
      'Their name, date of birth and background are stored securely.',
      'Health and development records are only kept if you agree, and you can change your mind at any time.',
      'You can correct the details or archive the profile whenever you need to.',
    ],
  },
};

export default function PrivacyNotice({ variant, accepted, onChange }) {
  const notice = NOTICES[variant];
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-xl border border-[#E4D9C6] bg-cream-100/60 px-4 py-3">
      <p className="text-sm text-slate-600">
        {notice.summary}{' '}
        <button type="button" onClick={() => setOpen((o) => !o)} className="text-brand-600 font-semibold hover:underline">
          {open ? 'Hide' : 'What does this mean?'}
        </button>
      </p>
      {open && (
        <ul className="list-disc pl-5 mt-1.5 space-y-0.5 text-sm text-slate-500">
          {notice.details.map((d) => (
            <li key={d}>{d}</li>
          ))}
        </ul>
      )}
      {open && notice.rights && (
        <>
          <p className="mt-2 text-sm font-semibold text-slate-600">{notice.rightsTitle}</p>
          <ul className="list-disc pl-5 mt-1 space-y-0.5 text-sm text-slate-500">
            {notice.rights.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </>
      )}
      <label className="flex items-center gap-2.5 mt-2.5 cursor-pointer">
        <input
          type="checkbox"
          required
          checked={accepted}
          onChange={(e) => onChange(e.target.checked)}
          className="h-4 w-4 accent-brand-600"
        />
        <span className="text-[15px] text-slate-700">
          {notice.rights ? 'I understand how my information is used and my rights' : 'I understand how this information is used'}
        </span>
      </label>
    </div>
  );
}
