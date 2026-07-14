export function PasswordPolicyChecklist({ password, username }: { password: string; username: string }) {
  const checks = [['12-128 characters', password.length >= 12 && password.length <= 128], ['Does not contain your username', !!username && !password.toLowerCase().includes(username.toLowerCase())], ['Not whitespace only', !!password.trim()]] as const;
  return <ul className="space-y-1 text-xs text-muted-foreground">{checks.map(([label, pass]) => <li key={label} className={pass ? 'text-emerald-300' : ''}>{pass ? '✓' : '○'} {label}</li>)}</ul>;
}
