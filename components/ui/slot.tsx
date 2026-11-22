// A few lines in place of @radix-ui/react-slot (which the host does not provide, so it would be a new runtime dependency):
// renders its only child with the props of the slot merged into the child's own (handlers run both, child first; class names and styles join).
import * as React from "react";

type AnyProps = Record<string, unknown>;

function mergeRefs<T>(...refs: Array<React.Ref<T> | undefined>): React.RefCallback<T> {
  return (node) => {
    for (const ref of refs) {
      if (typeof ref === "function") ref(node);
      else if (ref) (ref as React.MutableRefObject<T | null>).current = node;
    }
  };
}

function mergeProps(slot: AnyProps, child: AnyProps): AnyProps {
  const merged: AnyProps = { ...slot, ...child };
  for (const key of Object.keys(slot)) {
    const s = slot[key];
    const c = child[key];
    if (/^on[A-Z]/.test(key) && typeof s === "function" && typeof c === "function") {
      merged[key] = (...args: unknown[]) => {
        (c as (...a: unknown[]) => void)(...args);
        (s as (...a: unknown[]) => void)(...args);
      };
    } else if (key === "style") merged[key] = { ...(s as object), ...(c as object) };
    else if (key === "className") merged[key] = [s, c].filter(Boolean).join(" ");
  }
  return merged;
}

export const Slot = React.forwardRef<HTMLElement, React.HTMLAttributes<HTMLElement> & { children?: React.ReactNode }>(function Slot({ children, ...props }, ref) {
  if (!React.isValidElement(children)) return null;
  const child = children as React.ReactElement<AnyProps> & { ref?: React.Ref<HTMLElement> };
  const childRef = child.ref ?? (child.props.ref as React.Ref<HTMLElement> | undefined);
  return React.cloneElement(child, { ...mergeProps(props as AnyProps, child.props), ref: mergeRefs(ref, childRef) } as AnyProps);
});
