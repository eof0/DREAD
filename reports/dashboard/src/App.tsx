import { useEffect, useState } from "react";
import { getJSON } from "./api";
import { ReportView } from "./reports";
import { DreadAIView, CannonView, DatabaseView, DiscoverView, ScanView } from "./views";
import type { Product } from "./types";

type Section = { key: string; label: string; group: string };

const SECTIONS: Section[] = [
  { key: "register", label: "Exposure register", group: "Reports" },
  { key: "scan", label: "Full scan", group: "Assess" },
  { key: "discover", label: "Discovery", group: "Assess" },
  { key: "cannon", label: "Stress testing", group: "Assess" },
  { key: "dreadai", label: "DreadAI agent", group: "Operate" },
  { key: "database", label: "Databases", group: "Operate" },
];

const GROUPS = ["Reports", "Assess", "Operate"];

function useProducts() {
  const [products, setProducts] = useState<Product[]>([]);
  useEffect(() => {
    getJSON<Product[]>("/api/products").then(setProducts).catch(() => setProducts([]));
  }, []);
  return products;
}

export default function App() {
  const [active, setActive] = useState("register");
  const [reloadKey, setReloadKey] = useState(0);
  const products = useProducts();
  const implemented = products.filter((product) => product.status === "implemented").length;

  return (
    <div className="app-shell">
      <aside className="rail">
        <div className="brand">
          <span className="eyebrow">DREAD</span>
          <h1>Control</h1>
          <p>{implemented ? `${implemented} products live` : "Security assessment suite"}</p>
        </div>
        <nav>
          {GROUPS.map((group) => (
            <div className="nav-group" key={group}>
              <span className="nav-group-label">{group}</span>
              {SECTIONS.filter((section) => section.group === group).map((section) => (
                <button
                  key={section.key}
                  className={section.key === active ? "nav-item active" : "nav-item"}
                  onClick={() => setActive(section.key)}
                >
                  {section.label}
                </button>
              ))}
            </div>
          ))}
        </nav>
      </aside>

      <main className="main">
        {active === "register" && <ReportView reloadKey={reloadKey} />}
        {active === "scan" && <ScanView onReportsChanged={() => setReloadKey((key) => key + 1)} />}
        {active === "discover" && <DiscoverView />}
        {active === "cannon" && <CannonView />}
        {active === "dreadai" && <DreadAIView />}
        {active === "database" && <DatabaseView />}
      </main>
    </div>
  );
}
