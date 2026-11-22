// RadioGroup with the API of the shadcn one, written here: the host does not provide @radix-ui/react-radio-group.
// Cards are the usual look: `RadioGroupItem` is the whole card (a button with role="radio"); arrows move and select.
import * as React from "react";
import { cn } from "../../lib/utils";

interface RadioState {
  value: string;
  setValue: (v: string) => void;
  disabled: boolean;
}
const RadioContext = React.createContext<RadioState | null>(null);

function RadioGroup({ value, onValueChange, disabled = false, className, children, ...props }: { value: string; onValueChange: (v: string) => void; disabled?: boolean } & Omit<React.HTMLAttributes<HTMLDivElement>, "onChange">) {
  return (
    <RadioContext.Provider value={{ value, setValue: onValueChange, disabled }}>
      <div
        role="radiogroup"
        className={cn("grid gap-2", className)}
        onKeyDown={(e) => {
          const items = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="radio"]:not(:disabled)'));
          const i = items.indexOf(document.activeElement as HTMLButtonElement);
          if (i < 0) return;
          const step = e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : e.key === "ArrowUp" || e.key === "ArrowLeft" ? -1 : 0;
          if (!step) return;
          e.preventDefault();
          const next = items[(i + step + items.length) % items.length]!;
          next.focus();
          next.click();
        }}
        {...props}
      >
        {children}
      </div>
    </RadioContext.Provider>
  );
}

const RadioGroupItem = React.forwardRef<HTMLButtonElement, Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "value"> & { value: string }>(({ className, value, children, onClick, ...props }, ref) => {
  const s = React.useContext(RadioContext);
  if (!s) throw new Error("RadioGroupItem goes inside <RadioGroup>");
  const checked = s.value === value;
  return (
    <button
      ref={ref}
      type="button"
      role="radio"
      aria-checked={checked}
      data-state={checked ? "checked" : "unchecked"}
      tabIndex={checked ? 0 : -1}
      disabled={s.disabled || props.disabled}
      className={cn("flex w-full items-start gap-3 rounded-lg border border-border bg-card p-3 text-left text-sm text-card-foreground transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50 data-[state=checked]:border-foreground data-[state=checked]:bg-muted", className)}
      onClick={(e) => {
        onClick?.(e);
        if (!e.defaultPrevented) s.setValue(value);
      }}
      {...props}
    >
      <span aria-hidden className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border border-foreground">
        {checked ? <span className="size-2 rounded-full bg-foreground" /> : null}
      </span>
      <span className="min-w-0 flex-1">{children}</span>
    </button>
  );
});
RadioGroupItem.displayName = "RadioGroupItem";

export { RadioGroup, RadioGroupItem };
