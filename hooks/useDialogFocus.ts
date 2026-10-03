import { useEffect, useRef, type RefObject } from 'react';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Modal focus management (WCAG 2.4.3): moves focus into the dialog when it opens, keeps Tab
 * inside it, closes on Escape and returns focus to the element that opened it.
 */
export function useDialogFocus(ref: RefObject<HTMLElement | null>, isOpen: boolean, onClose: () => void) {
  // Latest onClose without re-running the effect: a new callback each render would steal focus mid-typing
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!isOpen) return;
    const opener = document.activeElement as HTMLElement | null;
    const dialog = ref.current;
    const focusables = () => Array.from(dialog?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []).filter((el) => el.offsetParent !== null);

    // Prefer the first form field so sign-in and similar dialogs are ready to type into
    const first = dialog?.querySelector<HTMLElement>('input:not([type="hidden"]), select, textarea') ?? focusables()[0] ?? dialog;
    first?.focus({ preventScroll: true });

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onCloseRef.current();
        return;
      }
      if (e.key !== 'Tab') return;
      const items = focusables();
      if (items.length === 0) return;
      const firstItem = items[0];
      const lastItem = items[items.length - 1];
      if (e.shiftKey && document.activeElement === firstItem) {
        e.preventDefault();
        lastItem.focus();
      } else if (!e.shiftKey && document.activeElement === lastItem) {
        e.preventDefault();
        firstItem.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      opener?.focus?.({ preventScroll: true });
    };
  }, [ref, isOpen]);
}
