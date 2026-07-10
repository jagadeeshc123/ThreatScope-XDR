import { CheckSquare } from 'lucide-react';

export function ManualValidationChecklist({ items }: { items: string[] }) {
  return <ul className="space-y-2">{items.map(item => <li key={item} className="flex gap-2 text-sm leading-5 text-muted-foreground"><CheckSquare className="mt-0.5 h-4 w-4 shrink-0 text-indigo-300" /><span>{item}</span></li>)}</ul>;
}
