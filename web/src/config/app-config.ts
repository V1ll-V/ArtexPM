import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "ARTEX PM",
  displayVersion: "v0.7.0",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX PM.`,
  meta: {
    title: "ARTEX PM v0.7.0 — 自主渗透测试控制台",
    description: "LLM 驱动的自主渗透测试系统控制台",
  },
};
