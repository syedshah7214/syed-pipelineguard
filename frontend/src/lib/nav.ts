import { BookOpen, LayoutDashboard, ListChecks, ScanSearch, type LucideIcon } from "lucide-react";

export interface NavItem { path: string; label: string; icon: LucideIcon; keywords: string }
export interface NavGroup { label: string; items: NavItem[] }

export const NAV: NavGroup[] = [
  { label: "Guard", items: [
    { path: "/", label: "Overview", icon: LayoutDashboard, keywords: "home dashboard history stats score" },
    { path: "/analyze", label: "Audit Workflows", icon: ScanSearch, keywords: "upload paste sample yaml repo github scan run" },
  ] },
  { label: "Policy", items: [
    { path: "/policies", label: "Rules", icon: ListChecks, keywords: "rules security supply chain reliability performance autofix" },
  ] },
  { label: "Platform", items: [
    { path: "/ci", label: "CI Integration", icon: BookOpen, keywords: "github actions cli sarif code scanning docs pipeline" },
  ] },
];
export const ALL_NAV = NAV.flatMap((g) => g.items);
