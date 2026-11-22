// A one-item accordion (a disclosure) written here: the host does not provide @radix-ui/react-accordion.
// `open` / `onOpenChange` make it controlled (the page keeps the state of a fold in `fold.ts`).
import * as React from "react";
import { cn } from "../../lib/utils";

function Accordion({ title, children, open, onOpenChange, defaultOpen = false, className, triggerClassName, id }: { title: React.ReactNode; children: React.ReactNode; open?: boolean; onOpenChange?: (open: boolean) => void; defaultOpen?: boolean; className?: string; triggerClassName?: string; id?: string }) {
  const [inner, setInner] = React.useState(defaultOpen);
  const isOpen = open ?? inner;
  const panel = React.useId();
  const toggle = () => {
    onOpenChange?.(!isOpen);
    if (open === undefined) setInner(!isOpen);
  };
  return (
    <div id={id} className={cn("rounded-lg border border-border bg-card text-card-foreground", className)} data-state={isOpen ? "open" : "closed"}>
      <button type="button" aria-expanded={isOpen} aria-controls={panel} onClick={toggle} className={cn("flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring", triggerClassName)}>
        <span className="min-w-0 flex-1">{title}</span>
        <span aria-hidden className={cn("text-muted-foreground transition-transform", isOpen ? "rotate-90" : "")}>›</span>
      </button>
      {isOpen ? (
        <div id={panel} className="border-t border-border px-3 py-3 text-sm">
          {children}
        </div>
      ) : null}
    </div>
  );
}

export { Accordion };
