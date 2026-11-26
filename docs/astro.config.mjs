// @ts-check
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

// Served by GitHub Pages as a project site under the account domain: https://docs.i2bskn.com/authlume/
export default defineConfig({
  site: "https://docs.i2bskn.com",
  base: "/authlume",
  devToolbar: { enabled: false },
  integrations: [
    starlight({
      title: "authlume",
      description:
        "Independently importable Go packages for passwords, server-side sessions, TOTP, WebAuthn and passkeys, OpenID Connect and MCP OAuth.",
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/i2bskn/authlume" },
      ],
      customCss: [
        "@fontsource/ibm-plex-sans/latin-400.css",
        "@fontsource/ibm-plex-sans/latin-500.css",
        "@fontsource/ibm-plex-sans/latin-600.css",
        "@fontsource/ibm-plex-mono/latin-400.css",
        "@fontsource/ibm-plex-mono/latin-500.css",
        "./src/styles/theme.css",
      ],
      components: {
        SiteTitle: "./src/components/SiteTitle.astro",
        Hero: "./src/components/Hero.astro",
        SocialIcons: "./src/components/SocialIcons.astro",
      },
      expressiveCode: {
        themes: ["github-dark-dimmed", "github-light"],
        styleOverrides: {
          borderRadius: "10px",
          borderColor: "var(--gh-line)",
          codeFontFamily: "var(--__sl-font-mono)",
          uiFontFamily: "var(--__sl-font)",
          codeFontSize: "0.8125rem",
          codeLineHeight: "1.7",
          frames: {
            shadowColor: "transparent",
            editorTabBarBackground: "var(--gh-surface-2)",
            editorActiveTabBackground: "var(--gh-surface)",
            editorActiveTabIndicatorTopColor: "var(--sl-color-accent)",
            editorActiveTabIndicatorBottomColor: "transparent",
            editorBackground: "var(--gh-surface)",
            terminalBackground: "var(--gh-surface)",
            terminalTitlebarBackground: "var(--gh-surface-2)",
          },
        },
      },
      head: [
        {
          // Copy each column header to its cells, so stacked tables on phones can label the values.
          tag: "script",
          content: `document.addEventListener("DOMContentLoaded", () => {
  for (const table of document.querySelectorAll(".sl-markdown-content table")) {
    const labels = [...table.querySelectorAll("thead th")].map((th) => th.textContent.trim());
    for (const row of table.querySelectorAll("tbody tr")) {
      [...row.children].forEach((cell, i) => {
        if (labels[i]) cell.dataset.label = labels[i];
      });
    }
  }
});`,
        },
      ],
      editLink: { baseUrl: "https://github.com/i2bskn/authlume/edit/main/docs/" },
      sidebar: [
        {
          label: "Getting started",
          items: ["getting-started/installation", "getting-started/quickstart"],
        },
        {
          label: "Guides",
          items: [
            "guides/password",
            "guides/sessions",
            "guides/totp",
            "guides/webauthn",
            "guides/oidc",
            "guides/mcp-oauth",
          ],
        },
        {
          label: "Reference",
          items: ["reference/design", "reference/mcp-store", "reference/status"],
        },
      ],
    }),
  ],
});
