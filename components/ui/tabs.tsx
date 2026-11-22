// Tabs with the API of the shadcn ones, written here: the host does not provide @radix-ui/react-tabs, and a new runtime dependency is not taken.
import * as React from "react";
import { cn } from "../../lib/utils";

interface TabsState {
  value: string;
  setValue: (v: string) => void;
  idBase: string;
}
const TabsContext = React.createContext<TabsState | null>(null);
const useTabs = (): TabsState => {
  const s = React.useContext(TabsContext);
  if (!s) throw new Error("Tabs parts go inside <Tabs>");
  return s;
};

function Tabs({ value, onValueChange, className, children }: { value: string; onValueChange: (v: string) => void; className?: string; children: React.ReactNode }) {
  const idBase = React.useId();
  return (
    <TabsContext.Provider value={{ value, setValue: onValueChange, idBase }}>
      <div className={className}>{children}</div>
    </TabsContext.Provider>
  );
}

/** The row of triggers: scrolls sideways on a narrow screen instead of wrapping; arrows, Home and End move between tabs. */
const TabsList = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(({ className, onKeyDown, ...props }, ref) => (
  <div
    ref={ref}
    role="tablist"
    className={cn("flex w-full items-center gap-1 overflow-x-auto border-b border-border [scrollbar-width:none]", className)}
    onKeyDown={(e) => {
      onKeyDown?.(e);
      if (e.defaultPrevented) return;
      const tabs = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]:not(:disabled)'));
      const i = tabs.indexOf(document.activeElement as HTMLButtonElement);
      if (i < 0) return;
      const next = e.key === "ArrowRight" ? (i + 1) % tabs.length : e.key === "ArrowLeft" ? (i - 1 + tabs.length) % tabs.length : e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : -1;
      if (next < 0) return;
      e.preventDefault();
      tabs[next]!.focus();
      tabs[next]!.click();
    }}
    {...props}
  />
));
TabsList.displayName = "TabsList";

const TabsTrigger = React.forwardRef<HTMLButtonElement, Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "value"> & { value: string }>(({ className, value, onClick, ...props }, ref) => {
  const s = useTabs();
  const active = s.value === value;
  return (
    <button
      ref={ref}
      type="button"
      role="tab"
      id={`${s.idBase}-t-${value}`}
      aria-selected={active}
      aria-controls={`${s.idBase}-p-${value}`}
      tabIndex={active ? 0 : -1}
      data-state={active ? "active" : "inactive"}
      className={cn("-mb-px inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap border-b-2 border-transparent px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring data-[state=active]:border-foreground data-[state=active]:text-foreground", className)}
      onClick={(e) => {
        onClick?.(e);
        if (!e.defaultPrevented) s.setValue(value);
      }}
      {...props}
    />
  );
});
TabsTrigger.displayName = "TabsTrigger";

function TabsContent({ value, className, children }: { value: string; className?: string; children: React.ReactNode }) {
  const s = useTabs();
  if (s.value !== value) return null;
  return (
    <div role="tabpanel" id={`${s.idBase}-p-${value}`} aria-labelledby={`${s.idBase}-t-${value}`} className={className}>
      {children}
    </div>
  );
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
