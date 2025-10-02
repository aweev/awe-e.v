// config/nav.ts

import { Role } from "@prisma/client";
import { ADMIN_ROLES } from "@/lib/auth/roles";

// Define the structure of a single navigation link
export interface NavLink {
    href: string;
    labelKey: string; // For i18n
    icon: string; // Icon name from your <Icon /> component
    allowedRoles: Role[]; // The roles that can see this link
}

// Define the structure for a group of links (e.g., a section in the sidebar)
export interface NavGroup {
    titleKey: string; // Optional title for the group
    links: NavLink[];
}

// --- MASTER NAVIGATION CONFIGURATION ---
export const navConfig: NavGroup[] = [
    // --- Main Group ---
    {
        titleKey: "nav.group.main",
        links: [
            {
                href: "/dashboard",
                labelKey: "nav.link.dashboard",
                icon: "layoutDashboard",
                // All authenticated users can see the dashboard link
                allowedRoles: Object.values(Role),
            },
            {
                href: "/projects",
                labelKey: "nav.link.projects",
                icon: "folderKanban",
                // Only roles that participate in projects should see this
                allowedRoles: [Role.ACTIVE_VOLUNTEER, Role.PROGRAM_MENTOR, ...ADMIN_ROLES],
            },
            {
                href: "/events",
                labelKey: "nav.link.events",
                icon: "calendar",
                // All authenticated users can see events
                allowedRoles: Object.values(Role),
            },
            {
                href: "/community",
                labelKey: "nav.link.community",
                icon: "users",
                // All non-admin members can see the community link
                allowedRoles: [
                    Role.ACTIVE_VOLUNTEER,
                    Role.PROGRAM_ALUMNI,
                    Role.CORPORATE_PARTNER,
                    Role.INDIVIDUAL_MAJOR_DONOR,
                    Role.INSTITUTIONAL_PARTNER,
                    Role.PROGRAM_MENTOR
                ],
            },
        ],
    },
    // --- Admin Group ---
    {
        titleKey: "nav.group.admin",
        links: [
            {
                href: "/admin/users",
                labelKey: "nav.link.userManagement",
                icon: "userCog",
                // Only Admin roles can see this
                allowedRoles: ADMIN_ROLES,
            },
            {
                href: "/admin/programs",
                labelKey: "nav.link.programManagement",
                icon: "folderCog",
                allowedRoles: ADMIN_ROLES,
            },
            {
                href: "/admin/settings",
                labelKey: "nav.link.settings",
                icon: "settings",
                allowedRoles: ADMIN_ROLES,
            },
        ],
    },
];