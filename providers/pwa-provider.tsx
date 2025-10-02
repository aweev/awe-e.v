// providers/pwa-provider.tsx
"use client";

import React, {
    createContext,
    useContext,
    useState,
    useEffect,
    useCallback,
    useRef,
    ReactNode,
} from "react";
import { Button } from "@/components/ui/button";
import { Icon } from "@/components/ui/icon";
import { motion, AnimatePresence } from "framer-motion";

// --- Type Definitions ---
interface BeforeInstallPromptEvent extends Event {
    readonly platforms: string[];
    readonly userChoice: Promise<{
        outcome: "accepted" | "dismissed";
        platform: string;
    }>;
    prompt(): Promise<void>;
}

interface PWAContextType {
    isInstallable: boolean;
    isUpdateAvailable: boolean;
    promptInstall: () => void;
    promptUpdate: () => void;
}

// --- Context and Hook ---
const PWAContext = createContext<PWAContextType | null>(null);

export const usePWA = () => {
    const context = useContext(PWAContext);
    if (!context) {
        throw new Error("usePWA must be used within a PWAProvider");
    }
    return context;
};

// --- Provider Props ---
interface PWAProviderProps {
    children: ReactNode;
    appName?: string;
    appDescription?: string;
    installPromptComponent?: React.ComponentType<{ onInstall: () => void; onDismiss: () => void }>;
    updatePromptComponent?: React.ComponentType<{ onUpdate: () => void; onDismiss: () => void }>;
}

const DISMISS_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

// --- Main Provider Component ---
export function PWAProvider({
    children,
    appName = "Our Awesome App",
    appDescription = "Install for a better experience and offline access.",
    installPromptComponent: CustomInstallPrompt,
    updatePromptComponent: CustomUpdatePrompt,
}: PWAProviderProps) {
    // Install state
    const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
    const [showInstallPrompt, setShowInstallPrompt] = useState(false);

    // Update state
    const [waitingWorker, setWaitingWorker] = useState<ServiceWorker | null>(null);
    const [showUpdatePrompt, setShowUpdatePrompt] = useState(false);
    const refreshingRef = useRef(false);

    // --- Install Logic ---
    useEffect(() => {
        const handleBeforeInstallPrompt = (e: Event) => {
            e.preventDefault();
            const lastDismissed = localStorage.getItem("pwaInstallDismissed");
            if (lastDismissed && Date.now() - parseInt(lastDismissed) < DISMISS_DURATION) {
                console.log("PWA install prompt deferred (user dismissed recently).");
                return;
            }
            setDeferredPrompt(e as BeforeInstallPromptEvent);
            setShowInstallPrompt(true);
        };

        const handleAppInstalled = () => {
            setDeferredPrompt(null);
            setShowInstallPrompt(false);
        };

        window.addEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
        window.addEventListener("appinstalled", handleAppInstalled);

        return () => {
            window.removeEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
            window.removeEventListener("appinstalled", handleAppInstalled);
        };
    }, []);

    const handleInstall = useCallback(async () => {
        if (!deferredPrompt) return;
        deferredPrompt.prompt();
        const { outcome } = await deferredPrompt.userChoice;
        if (outcome === "accepted") {
            console.log("PWA install accepted.");
        } else {
            console.log("PWA install dismissed.");
            // Treat explicit dismissal same as closing the prompt
            // Mark dismissal and keep final closing logic below centralized
            localStorage.setItem("pwaInstallDismissed", Date.now().toString());
        }
        setDeferredPrompt(null);
        setShowInstallPrompt(false);
    }, [deferredPrompt]);

    const handleInstallDismiss = useCallback(() => {
        setShowInstallPrompt(false);
        localStorage.setItem("pwaInstallDismissed", Date.now().toString());
    }, []);

    // --- Update Logic ---
    useEffect(() => {
        if (typeof window === "undefined" || !("serviceWorker" in navigator)) return;

        const onUpdate = (registration: ServiceWorkerRegistration) => {
            setWaitingWorker(registration.waiting);
            setShowUpdatePrompt(true);
        };

        const onControllerChange = () => {
            if (refreshingRef.current) return;
            refreshingRef.current = true;
            window.location.reload();
        };

        navigator.serviceWorker.ready.then((registration) => {
            if (registration.waiting) {
                onUpdate(registration);
            }
            registration.addEventListener("updatefound", () => {
                const newWorker = registration.installing;
                if (newWorker) {
                    newWorker.addEventListener("statechange", () => {
                        if (newWorker.state === "installed" && navigator.serviceWorker.controller) {
                            onUpdate(registration);
                        }
                    });
                }
            });
        });

        navigator.serviceWorker.addEventListener("controllerchange", onControllerChange);

        return () => {
            navigator.serviceWorker.removeEventListener("controllerchange", onControllerChange);
        };
    }, []);

    const handleUpdate = useCallback(() => {
        if (waitingWorker) {
            waitingWorker.postMessage({ type: "SKIP_WAITING" });
            setShowUpdatePrompt(false);
        }
    }, [waitingWorker]);

    const handleUpdateDismiss = useCallback(() => {
        setShowUpdatePrompt(false);
    }, []);

    // --- Context Value ---
    const contextValue: PWAContextType = {
        isInstallable: !!deferredPrompt,
        isUpdateAvailable: !!waitingWorker,
        promptInstall: handleInstall,
        promptUpdate: handleUpdate,
    };

    return (
        <PWAContext.Provider value={contextValue}>
            {children}

            <AnimatePresence>
                {showInstallPrompt &&
                    (CustomInstallPrompt ? (
                        <CustomInstallPrompt onInstall={handleInstall} onDismiss={handleInstallDismiss} />
                    ) : (
                        <DefaultInstallPrompt
                            onInstall={handleInstall}
                            onDismiss={handleInstallDismiss}
                            appName={appName}
                            appDescription={appDescription}
                        />
                    ))}
            </AnimatePresence>

            <AnimatePresence>
                {showUpdatePrompt &&
                    (CustomUpdatePrompt ? (
                        <CustomUpdatePrompt onUpdate={handleUpdate} onDismiss={handleUpdateDismiss} />
                    ) : (
                        <DefaultUpdatePrompt onUpdate={handleUpdate} onDismiss={handleUpdateDismiss} />
                    ))}
            </AnimatePresence>
        </PWAContext.Provider>
    );
}

// --- Default UI Components ---

const PromptWrapper = ({ children }: { children: ReactNode }) => (
    <motion.div
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 50 }}
        transition={{ type: "spring", stiffness: 300, damping: 30 }}
        className="fixed bottom-4 left-4 right-4 z-50 max-w-md mx-auto"
    >
        <div className="bg-background border border-border rounded-lg shadow-lg p-4 w-full">
            {children}
        </div>
    </motion.div>
);

const DefaultInstallPrompt = ({
    onInstall,
    onDismiss,
    appName,
    appDescription,
}: {
    onInstall: () => void;
    onDismiss: () => void;
    appName: string;
    appDescription: string;
}) => (
    <PromptWrapper>
        <div className="flex items-start gap-4">
            <div className="p-2 bg-primary/10 rounded-lg flex-shrink-0">
                <Icon name='download' className="h-6 w-6 text-primary" />
            </div>
            <div className="flex-1">
                <h3 className="font-semibold text-base mb-1">Install {appName}</h3>
                <p className="text-sm text-muted-foreground mb-4">{appDescription}</p>
                <div className="flex gap-2">
                    <Button size="sm" onClick={onInstall}>
                        Install
                    </Button>
                    <Button size="sm" variant="outline" onClick={onDismiss}>
                        Later
                    </Button>
                </div>
            </div>
            <Button size="icon" variant="ghost" onClick={onDismiss} className="h-7 w-7 flex-shrink-0">
                <Icon name='x' className="h-4 w-4" />
            </Button>
        </div>
    </PromptWrapper>
);

const DefaultUpdatePrompt = ({
    onUpdate,
    onDismiss,
}: {
    onUpdate: () => void;
    onDismiss: () => void;
}) => (
    <PromptWrapper>
        <div className="flex items-start gap-4">
            <div className="p-2 bg-blue-500/10 rounded-lg flex-shrink-0">
                <Icon name='refreshCw' className="h-6 w-6 text-blue-500" />
            </div>
            <div className="flex-1">
                <h3 className="font-semibold text-base mb-1">Update Available</h3>
                <p className="text-sm text-muted-foreground mb-4">
                    A new version of the app is ready. Reload to get the latest features.
                </p>
                <div className="flex gap-2">
                    <Button size="sm" onClick={onUpdate}>
                        Reload & Update
                    </Button>
                    <Button size="sm" variant="outline" onClick={onDismiss}>
                        Later
                    </Button>
                </div>
            </div>
        </div>
    </PromptWrapper>
);