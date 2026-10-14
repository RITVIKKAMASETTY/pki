import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface Props {
  content: string;
  isUser?: boolean;
}

export function MarkdownView({ content, isUser = false }: Props) {
  if (isUser) {
    return <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{content}</div>;
  }

  return (
    <div className="markdown-body" style={{ color: '#0f172a', fontSize: '13.5px', lineHeight: 1.65 }}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ node, ...props }) => (
            <h1
              style={{
                fontSize: '16px',
                fontWeight: 800,
                color: '#0f172a',
                margin: '14px 0 8px',
                paddingBottom: '4px',
                borderBottom: '2px solid #fde047',
              }}
              {...props}
            />
          ),
          h2: ({ node, ...props }) => (
            <h2
              style={{
                fontSize: '15px',
                fontWeight: 750,
                color: '#0f172a',
                margin: '12px 0 6px',
              }}
              {...props}
            />
          ),
          h3: ({ node, ...props }) => (
            <h3
              style={{
                fontSize: '14px',
                fontWeight: 700,
                color: '#854d0e',
                margin: '10px 0 4px',
              }}
              {...props}
            />
          ),
          h4: ({ node, ...props }) => (
            <h4
              style={{
                fontSize: '13px',
                fontWeight: 700,
                color: '#a16207',
                margin: '8px 0 4px',
              }}
              {...props}
            />
          ),
          p: ({ node, ...props }) => (
            <p style={{ margin: '6px 0', wordBreak: 'break-word' }} {...props} />
          ),
          strong: ({ node, ...props }) => (
            <strong style={{ fontWeight: 700, color: '#0f172a' }} {...props} />
          ),
          em: ({ node, ...props }) => (
            <em style={{ color: '#334155', fontStyle: 'italic' }} {...props} />
          ),
          ul: ({ node, ...props }) => (
            <ul style={{ margin: '6px 0 6px 18px', paddingLeft: '4px' }} {...props} />
          ),
          ol: ({ node, ...props }) => (
            <ol style={{ margin: '6px 0 6px 18px', paddingLeft: '4px' }} {...props} />
          ),
          li: ({ node, ...props }) => (
            <li style={{ margin: '3px 0' }} {...props} />
          ),
          table: ({ node, ...props }) => (
            <div style={{ overflowX: 'auto', margin: '12px 0', borderRadius: '8px', border: '1px solid #e2e8f0', boxShadow: '0 1px 4px rgba(0,0,0,0.03)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12.5px', background: '#ffffff' }} {...props} />
            </div>
          ),
          thead: ({ node, ...props }) => (
            <thead style={{ background: '#fef9c3', borderBottom: '2px solid #facc15' }} {...props} />
          ),
          tbody: ({ node, ...props }) => (
            <tbody {...props} />
          ),
          tr: ({ node, ...props }) => (
            <tr style={{ borderBottom: '1px solid #f1f5f9' }} {...props} />
          ),
          th: ({ node, ...props }) => (
            <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 700, color: '#854d0e', whiteSpace: 'nowrap' }} {...props} />
          ),
          td: ({ node, ...props }) => (
            <td style={{ padding: '8px 12px', color: '#1e293b', verticalAlign: 'top' }} {...props} />
          ),
          blockquote: ({ node, ...props }) => (
            <blockquote
              style={{
                borderLeft: '4px solid #eab308',
                background: '#fefce8',
                padding: '8px 12px',
                margin: '8px 0',
                borderRadius: '0 6px 6px 0',
                color: '#854d0e',
                fontSize: '13px',
              }}
              {...props}
            />
          ),
          code: ({ node, className, children, ...props }: any) => {
            const isInline = !className;
            if (isInline) {
              return (
                <code
                  style={{
                    background: '#fef9c3',
                    color: '#854d0e',
                    border: '1px solid #fde047',
                    padding: '2px 5px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 600,
                  }}
                  {...props}
                >
                  {children}
                </code>
              );
            }
            return (
              <pre
                style={{
                  background: '#18181b',
                  color: '#fef08a',
                  padding: '12px 14px',
                  borderRadius: '8px',
                  overflowX: 'auto',
                  fontSize: '12px',
                  fontFamily: 'var(--font-mono)',
                  margin: '8px 0',
                  border: '1px solid #27272a',
                }}
              >
                <code {...props}>{children}</code>
              </pre>
            );
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
