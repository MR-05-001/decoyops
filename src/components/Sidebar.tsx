import { Shield, LayoutDashboard, Server, Archive, Settings } from 'lucide-react';
import { cn } from '../lib/utils';

interface SidebarProps {
  currentTab: string;
  setTab: (tab: string) => void;
}

export function Sidebar({ currentTab, setTab }: SidebarProps) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'decoys', label: 'Decoys', icon: Server },
    { id: 'quarantine', label: 'Quarantine', icon: Archive },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <div className="w-64 border-r border-border/50 glass-header flex flex-col h-screen shrink-0">
      <div className="p-6 flex items-center gap-3">
        <Shield className="w-8 h-8 text-primary" />
        <span className="font-bold text-xl tracking-tight text-foreground">DecoyOps</span>
      </div>
      <nav className="flex-1 px-4 space-y-2 mt-4">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setTab(item.id)}
              className={cn(
                "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
                isActive 
                  ? "bg-primary/15 text-primary shadow-sm ring-1 ring-primary/30" 
                  : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground"
              )}
            >
              <Icon className="w-5 h-5" />
              {item.label}
            </button>
          );
        })}
      </nav>
      <div className="p-6 border-t border-border/50 text-xs text-muted-foreground">
        Version 0.1.0
      </div>
    </div>
  );
}
