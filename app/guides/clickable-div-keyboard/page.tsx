import React from 'react';
import type { Metadata } from 'next';
import { CodeBlock, TestStep, ZelsisCatches, ScanCta } from '@/components/guides/GuideParts';

export const metadata: Metadata = {
  title: 'div onClick Is Not a Button: Keyboard Users Cannot Reach It - Zelsis Guides',
  description:
    'A <div onClick> cannot be focused with Tab or pressed with Enter, and screen readers do not call it a button. Why it loses customers, the <button> fix, the role="button" fallback and how to test it.',
};

const H2 = 'text-xl font-semibold text-white';

export default function ClickableDivKeyboardPage() {
  return (
    <article className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">A div with onClick is not a button</h1>
      <p className="text-zinc-400">
        The Pay button looks fine and works with a mouse. A customer who uses the keyboard presses Tab, and focus jumps straight past it.
        A screen reader reads the label as plain text. Neither of them can pay, and neither of them files a bug report. They leave.
      </p>

      <section className="space-y-3">
        <h2 className={H2}>Why it happens</h2>
        <p className="text-zinc-300">
          A <code>&lt;button&gt;</code> gets three things from the browser for free: it is in the Tab order, Enter and Space press it, and
          assistive technology announces it as a button. A <code>&lt;div&gt;</code> or <code>&lt;span&gt;</code> gets none of them. Adding{' '}
          <code>onClick</code> only handles the mouse.
        </p>
        <CodeBlock
          tone="bad"
          label="Bad: mouse only"
          code={`<div className="pay-button" onClick={handlePay}>
  Pay now
</div>`}
        />
        <p className="text-zinc-300">
          The cost is real. People who cannot use a mouse, people with a broken trackpad and power users who move by keyboard all hit the
          same wall. In many markets, including the US and the EU under the European Accessibility Act, an online checkout that keyboard
          users cannot complete is also a legal risk.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>The fix: use a real button</h2>
        <p className="text-zinc-300">
          Swap the element. Set <code>type=&quot;button&quot;</code> so it does not submit a surrounding form by accident, and reset the
          default styles if they get in the way. Keep a visible focus style so keyboard users can see where they are.
        </p>
        <CodeBlock
          tone="good"
          label="Good: native button"
          code={`<button type="button" className="pay-button" onClick={handlePay}>
  Pay now
</button>

/* CSS */
.pay-button { all: unset; cursor: pointer; /* your styles */ }
.pay-button:focus-visible { outline: 2px solid #34d399; outline-offset: 2px; }`}
        />
        <p className="text-zinc-300">
          If the click goes to another page, use a link (<code>&lt;a href&gt;</code> or your framework&apos;s <code>Link</code>) instead.
          Links also work with the keyboard, open in a new tab and show the address on hover.
        </p>
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>When you cannot change the element</h2>
        <p className="text-zinc-300">
          Sometimes a library renders the wrapper for you. Then add what the browser would have given a button: a role, a place in the Tab
          order and a key handler for Enter and Space.
        </p>
        <CodeBlock
          tone="good"
          label="Fallback: role, tabIndex and keys"
          code={`<div
  role="button"
  tabIndex={0}
  onClick={handlePay}
  onKeyDown={(e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault(); // stop Space from scrolling the page
      handlePay();
    }
  }}
>
  Pay now
</div>`}
        />
      </section>

      <section className="space-y-3 border-t border-white/10 pt-6">
        <h2 className={H2}>Verify it</h2>
        <TestStep>
          Put the mouse away and go through your main flow (sign up, checkout, settings) with Tab, Shift+Tab, Enter and Space. Every action
          must be reachable and you must always see where the focus is. In code, the <code>jsx-a11y</code> ESLint rules{' '}
          <code>click-events-have-key-events</code> and <code>no-static-element-interactions</code> catch the same pattern, and an automated
          check such as Lighthouse or axe reports missing roles.
        </TestStep>
      </section>

      <ZelsisCatches rules={[{ id: 'UI-A11Y-02', title: 'Clickable div or span without role, tabIndex or keyboard handler' }]}>
        Zelsis flags <code>&lt;div&gt;</code> and <code>&lt;span&gt;</code> elements with <code>onClick</code> and no role, tabIndex or key
        handler, and suggests the <code>&lt;button&gt;</code> fix on the pull request.
      </ZelsisCatches>

      <ScanCta />
    </article>
  );
}
