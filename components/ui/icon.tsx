// components/ui/icon.tsx
import React from "react";
import type { LucideProps } from "lucide-react";
import { ICON_MAP, type IconName } from "@/constants/icons";
import { cn } from "@/lib/utils";

export interface IconProps extends Omit<LucideProps, "ref"> {
  name: IconName;
  fallback?: React.ComponentType<LucideProps>;
  "aria-label"?: string;
}

export const Icon = React.forwardRef<SVGSVGElement, IconProps>(
  (
    { name, className, fallback: Fallback, "aria-label": ariaLabel, ...props },
    ref
  ) => {
    const LucideIcon = ICON_MAP[name];

    if (!LucideIcon) {
      if (Fallback)
        return (
          <Fallback ref={ref} className={cn("h-4 w-4", className)} {...props} />
        );
      console.warn(`Icon "${name}" not found`);
      return null;
    }

    return (
      <LucideIcon
        ref={ref}
        className={cn("h-4 w-4", className)}
        strokeWidth={1.5}
        aria-label={ariaLabel ?? name}
        {...props}
      />
    );
  }
);
Icon.displayName = "Icon";

export { IconName };
