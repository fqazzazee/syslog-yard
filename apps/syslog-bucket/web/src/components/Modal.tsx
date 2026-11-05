import type { ReactNode } from "react";
import { Dialog } from "../../../../shared/web/src/Dialog";

// Modal is the bucket's name for the suite-wide Dialog (focus trap, Escape,
// focus return, aria-modal); kept so the many bucket dialogs read as before.
export default function Modal({
  title,
  onClose,
  children,
  size,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  size?: "sm" | "md" | "lg";
}) {
  return (
    <Dialog title={title} onClose={onClose} size={size}>
      {children}
    </Dialog>
  );
}
