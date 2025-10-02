// lib/animations.ts
import { Variants, Easing } from "framer-motion";

const easings = {
  easeOut: [0.0, 0.0, 0.2, 1] as Easing,
  easeIn: [0.4, 0.0, 1, 1] as Easing,
  easeInOut: [0.4, 0.0, 0.2, 1] as Easing,
  backOut: [0.34, 1.56, 0.64, 1] as Easing,
  anticipate: [0.2, 1, 0.4, 1] as Easing,
} as const;

export const dignifiedReveal: Variants = {
  hidden: {
    opacity: 0,
    y: 30,
  },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.8,
      ease: [0.6, 0.05, 0.01, 0.9] as Easing,
    },
  },
};

export const subtleQuickFadeIn: Variants = {
  hidden: {
    opacity: 0,
  },
  visible: {
    opacity: 1,
    transition: {
      duration: 0.6,
      ease: easings.easeOut,
    },
  },
};

export const staggeredContainer: Variants = {
  hidden: {
    opacity: 0,
  },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.15,
      delayChildren: 0.2,
    },
  },
};

export const smoothScale: Variants = {
  hidden: {
    opacity: 0,
    scale: 0.95,
  },
  visible: {
    opacity: 1,
    scale: 1,
    transition: {
      duration: 0.6,
      ease: easings.easeOut,
    },
  },
};

export const slideUp: Variants = {
  hidden: {
    opacity: 0,
    y: 50,
  },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.7,
      ease: easings.easeOut,
    },
  },
};

export const floatingElement: Variants = {
  hidden: {
    opacity: 0,
    y: 20,
    scale: 0.9,
  },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.8,
      ease: easings.easeOut,
    },
  },
  float: {
    y: [-10, 10, -10],
    rotate: [-2, 2, -2],
    transition: {
      duration: 6,
      repeat: Infinity,
      ease: easings.easeInOut,
    },
  },
};

export const cardHover: Variants = {
  rest: {
    scale: 1,
    rotateX: 0,
    rotateY: 0,
  },
  hover: {
    scale: 1.03,
    rotateX: 6,
    rotateY: -6,
    transition: {
      type: "spring",
      stiffness: 200,
      damping: 15,
    },
  },
};

export const textReveal: Variants = {
  hidden: {
    opacity: 0,
    y: 30,
    scale: 0.98,
  },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.7,
      ease: [0.25, 0.25, 0.25, 1] as Easing,
    },
  },
};

export const progressiveBlur: Variants = {
  hidden: {
    opacity: 0,
    filter: "blur(10px)",
  },
  visible: {
    opacity: 1,
    filter: "blur(0px)",
    transition: {
      duration: 1.2,
      ease: easings.easeOut,
    },
  },
};

// Common button animations
export const buttonVariants: Variants = {
  idle: { scale: 1 },
  hover: {
    scale: 1.05,
    transition: {
      duration: 0.3,
      ease: easings.easeOut,
    },
  },
  tap: {
    scale: 0.95,
    transition: {
      duration: 0.1,
      ease: easings.easeOut,
    },
  },
};

// Icon animations
export const iconVariants: Variants = {
  initial: { rotate: 0, scale: 1 },
  hover: {
    rotate: [0, -5, 5, 0],
    scale: 1.1,
    transition: {
      rotate: {
        duration: 0.6,
        ease: easings.easeInOut,
      },
      scale: {
        duration: 0.3,
        ease: easings.easeOut,
      },
    },
  },
};

// Dropdown animations
export const dropdownVariants: Variants = {
  hidden: {
    opacity: 0,
    scale: 0.95,
    y: -10,
  },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      duration: 0.2,
      ease: easings.easeOut,
      staggerChildren: 0.05,
    },
  },
  exit: {
    opacity: 0,
    scale: 0.95,
    y: -10,
    transition: {
      duration: 0.15,
      ease: easings.easeIn,
    },
  },
};

export const itemVariants: Variants = {
  hidden: { opacity: 0, x: -10 },
  visible: {
    opacity: 1,
    x: 0,
    transition: {
      duration: 0.15,
      ease: easings.easeOut,
    },
  },
};

// Container animations
export const containerVariants: Variants = {
  initial: { scale: 1 },
  hover: {
    scale: 1.02,
    transition: {
      duration: 0.3,
      ease: easings.easeOut,
    },
  },
  tap: {
    scale: 0.98,
    transition: {
      duration: 0.1,
      ease: easings.easeOut,
    },
  },
};

// Animation presets for different content types
export const heroAnimations = {
  container: staggeredContainer,
  badge: slideUp,
  headline: textReveal,
  cta: smoothScale,
  floatingCard: floatingElement,
};

export const sectionAnimations = {
  title: dignifiedReveal,
  content: staggeredContainer,
  card: cardHover,
};

// Sparkle animation
export const sparkleVariants: Variants = {
  initial: {
    scale: 0,
    rotate: 0,
    opacity: 0,
    x: 0,
    y: 0,
  },
  animate: {
    scale: [0, 1, 0],
    rotate: 360,
    opacity: [0, 1, 0],
    x: [0, -10, 10, 0],
    y: [0, -8, 8, 0],
    transition: {
      duration: 2,
      repeat: Infinity,
      ease: easings.easeInOut,
      times: [0, 0.2, 0.8, 1],
    },
  },
};

// Mobile menu animations
export const mobileMenuVariants: Variants = {
  hidden: { opacity: 0, y: -10 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.3,
      ease: easings.easeOut,
      staggerChildren: 0.1,
      delayChildren: 0.1,
    },
  },
};

export const mobileItemVariants: Variants = {
  hidden: { opacity: 0, x: -20 },
  visible: {
    opacity: 1,
    x: 0,
    transition: {
      duration: 0.3,
      ease: easings.easeOut,
    },
  },
};
