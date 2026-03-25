import { useState, useRef, useEffect } from 'react';

interface ExportFormat {
  label: string;
  value: 'json' | 'csv';
  extension: string;
}

interface ExportButtonProps<T> {
  data: T[];
  filename: string;
  csvHeaders: { key: keyof T; label: string }[];
}

const formats: ExportFormat[] = [
  { label: 'JSON', value: 'json', extension: 'json' },
  { label: 'CSV', value: 'csv', extension: 'csv' },
];

export function ExportButton<T extends object>({ data, filename, csvHeaders }: ExportButtonProps<T>) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const downloadFile = (content: string, extension: string) => {
    const blob = new Blob([content], { type: extension === 'json' ? 'application/json' : 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${filename}.${extension}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setIsOpen(false);
  };

  const exportJSON = () => {
    const content = JSON.stringify(data, null, 2);
    downloadFile(content, 'json');
  };

  const escapeCSV = (value: unknown): string => {
    if (value === null || value === undefined) return '';
    const str = String(value);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const exportCSV = () => {
    const headers = csvHeaders.map(h => h.label).join(',');
    const rows = data.map(row =>
      csvHeaders.map(h => {
        const value = row[h.key];
        if (Array.isArray(value)) {
          return escapeCSV(value.join('; '));
        }
        return escapeCSV(value);
      }).join(',')
    );
    const content = [headers, ...rows].join('\n');
    downloadFile(content, 'csv');
  };

  const handleExport = (format: ExportFormat['value']) => {
    if (format === 'json') {
      exportJSON();
    } else {
      exportCSV();
    }
  };

  return (
    <div ref={dropdownRef} style={{ position: 'relative' }}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{
          padding: '0.75rem 1rem',
          background: 'var(--bg-tertiary)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          color: 'var(--text-primary)',
          fontSize: '0.875rem',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          whiteSpace: 'nowrap',
        }}
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
        Export
      </button>

      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 4px)',
            right: 0,
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '4px',
            minWidth: '120px',
            zIndex: 100,
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
          }}
        >
          {formats.map((format) => (
            <button
              key={format.value}
              onClick={() => handleExport(format.value)}
              style={{
                width: '100%',
                padding: '0.5rem 0.75rem',
                background: 'transparent',
                border: 'none',
                borderRadius: '4px',
                color: 'var(--text-primary)',
                fontSize: '0.875rem',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background 0.15s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'var(--bg-tertiary)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'transparent';
              }}
            >
              {format.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
