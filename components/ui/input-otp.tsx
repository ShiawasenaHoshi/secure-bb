// A one-time code field with separate cells, written here (the `input-otp` package would be a new runtime dependency).
// One real input holds the digits (so paste, autofill and the keyboard of a phone work); the cells only draw it.
// The last digit calls `onComplete` by itself; Enter calls it too, when the code is full.
import * as React from "react";
import { cn } from "../../lib/utils";

interface InputOTPProps {
  value: string;
  onChange: (v: string) => void;
  onComplete?: (v: string) => void;
  length?: number;
  disabled?: boolean;
  invalid?: boolean;
  autoFocus?: boolean;
  "aria-label"?: string;
  className?: string;
}

const InputOTP = React.forwardRef<HTMLInputElement, InputOTPProps>(({ value, onChange, onComplete, length = 6, disabled, invalid, autoFocus, className, ...rest }, ref) => {
  const [focused, setFocused] = React.useState(false);
  const set = (raw: string) => {
    const v = raw.replace(/\D/g, "").slice(0, length);
    onChange(v);
    if (v.length === length && value.length !== length) onComplete?.(v);
  };
  return (
    <div className={cn("relative inline-flex gap-1.5", className)}>
      <input
        ref={ref}
        className="absolute inset-0 h-full w-full cursor-text opacity-0"
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={length}
        value={value}
        disabled={disabled}
        autoFocus={autoFocus}
        aria-label={rest["aria-label"] ?? "Код из приложения-аутентификатора"}
        aria-invalid={invalid || undefined}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onChange={(e) => set(e.target.value)}
        onKeyDown={(e) => {
          if (e.key !== "Enter") return;
          e.preventDefault();
          if (value.length === length) onComplete?.(value);
        }}
      />
      {Array.from({ length }, (_, i) => (
        <span
          key={i}
          aria-hidden
          data-active={focused && i === Math.min(value.length, length - 1) ? "true" : undefined}
          className={cn("flex size-10 items-center justify-center rounded-md border bg-background font-mono text-lg", invalid ? "border-destructive" : "border-input", "data-[active=true]:ring-2 data-[active=true]:ring-ring", disabled ? "opacity-50" : "")}
        >
          {value[i] ?? ""}
        </span>
      ))}
    </div>
  );
});
InputOTP.displayName = "InputOTP";

export { InputOTP };
