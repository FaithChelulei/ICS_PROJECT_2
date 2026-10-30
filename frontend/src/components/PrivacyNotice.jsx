// KDPA s.29 (duty to notify): tell people how their data is used BEFORE it
// is collected. Shown on the account request form and the child
// registration form; accepting it is required, and the version accepted is
// stored by the backend (services/privacyNotice.js -- keep the two versions
// in step when the text changes).
export const PRIVACY_NOTICE_VERSION = '2026-10';

const NOTICES = {
  account: {
    title: 'How your information is used',
    points: [
      'Your name and email are used only to create and secure your account: sign-in, verification codes and security alerts.',
      'A System Administrator reviews your request before any account is created.',
      'Your activity in the system is recorded in an audit log and checked for unusual behaviour, to protect the children’s data held here.',
      'Your data is never sold or shared outside this system.',
    ],
  },
  child: {
    title: 'How this child’s information is used',
    points: [
      'The child’s name, date of birth and family background are stored encrypted, separately from their developmental records.',
      'Only you, as the registering caregiver, can view or change them. Every access is logged.',
      'Developmental and health records are stored only if you give that consent, which you can withdraw at any time.',
      'You can correct the child’s details, or archive the profile. Archived profiles are frozen, and their identity is anonymised after the retention period.',
    ],
  },
};

export default function PrivacyNotice({ variant, accepted, onChange }) {
  const notice = NOTICES[variant];
  return (
    <div className="rounded-xl border border-[#E4D9C6] bg-cream-100/60 px-4 py-3.5">
      <div className="text-[15px] font-semibold text-ink mb-1.5">{notice.title}</div>
      <ul className="list-disc pl-5 space-y-1 text-sm text-slate-600 mb-3">
        {notice.points.map((p) => (
          <li key={p}>{p}</li>
        ))}
      </ul>
      <label className="flex items-start gap-3 cursor-pointer">
        <input
          type="checkbox"
          required
          checked={accepted}
          onChange={(e) => onChange(e.target.checked)}
          className="mt-1 h-4 w-4 accent-brand-600"
        />
        <span className="text-[15px] text-slate-700">I have read how this information is used.</span>
      </label>
      <div className="text-xs text-slate-400 mt-2">
        Under the Kenya Data Protection Act 2019. Notice version {PRIVACY_NOTICE_VERSION}.
      </div>
    </div>
  );
}
