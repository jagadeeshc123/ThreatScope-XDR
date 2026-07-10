import { UploadCloud } from 'lucide-react';
import clsx from 'clsx';

export function ImportDropzone({
  accept,
  disabled,
  file,
  onFile,
}: {
  accept: string;
  disabled?: boolean;
  file: File | null;
  onFile: (file: File) => void;
}) {
  const handleFiles = (files: FileList | null) => {
    const selected = files?.[0];
    if (selected) onFile(selected);
  };

  return (
    <label
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => {
        event.preventDefault();
        if (!disabled) handleFiles(event.dataTransfer.files);
      }}
      className={clsx(
        'flex min-h-56 cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-indigo-400/40 bg-indigo-500/10 px-6 py-10 text-center transition-colors hover:bg-indigo-500/15',
        disabled && 'cursor-not-allowed opacity-60',
      )}
    >
      <input type="file" accept={accept} disabled={disabled} className="sr-only" onChange={event => handleFiles(event.target.files)} />
      <div className="rounded-full bg-indigo-500/15 p-3 text-indigo-200">
        <UploadCloud className="h-7 w-7" />
      </div>
      <p className="mt-4 text-sm font-semibold text-foreground">{file ? file.name : 'Drop a definition file here'}</p>
      <p className="mt-2 text-sm text-muted-foreground">{file ? `${file.size.toLocaleString()} bytes selected` : 'or choose a file from disk'}</p>
    </label>
  );
}

