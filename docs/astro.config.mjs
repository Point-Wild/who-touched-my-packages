import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import starlightImageZoom from 'starlight-image-zoom';
import starlightThemeFlexoki from 'starlight-theme-flexoki';

// https://astro.build/config
export default defineConfig({
    site: 'https://Point-Wild.github.io/who-touched-my-packages',
    base: '/who-touched-my-packages/',
    integrations: [
        sitemap({
            changefreq: 'weekly',
            priority: 0.7,
            lastmod: new Date()
        }),
        starlight({
            components: {
                SocialIcons: './src/components/SocialIcons.astro',
            },
            plugins: [
                starlightImageZoom({ showCaptions: true }),
                starlightThemeFlexoki(),
            ],
            title: 'Who Touched My Deps?',
            description: 'A beautiful CLI tool for auditing dependencies and finding vulnerabilities',
            social: [
                { label: 'GitHub', href: 'https://github.com/point-wild/who-touched-my-deps', icon: 'github' },
            ],
            editLink: {
                baseUrl: 'https://github.com/point-wild/who-touched-my-deps/edit/main/docs/',
            },
            sidebar: [
                {
                    label: 'Getting Started',
                    items: [
                        { label: 'Introduction', link: '/' },
                        { label: 'Installation', link: '/getting-started/installation/' },
                        { label: 'Quick Start', link: '/quick-start/' },
                    ],
                },
                {
                    label: 'Usage',
                    items: [
                        { label: 'Command Line Options', link: '/usage/cli-options/' },
                        { label: 'Scanning Projects', link: '/usage/scanning/' },
                        { label: 'CI/CD Integration', link: '/usage/ci-cd/' },
                    ],
                },
                {
                    label: 'Data Sources',
                    items: [
                        { label: 'Overview', link: '/data-sources/overview/' },
                        { label: 'OSV', link: '/data-sources/osv/' },
                        { label: 'GitHub Advisory', link: '/data-sources/github/' },
                    ],
                },
                {
                    label: 'Guides',
                    items: [
                        { label: 'Understanding Output', link: '/guides/output/' },
                        { label: 'Filtering Results', link: '/guides/filtering/' },
                        { label: 'JSON Output', link: '/guides/json/' },
                    ],
                },
            ],
            customCss: [
                './src/styles/custom.css',
            ],
        }),
    ],
    vite: {
        resolve: {
            preserveSymlinks: true,
        },
        server: {
            fs: {
                allow: ['..'],
            }
        }
    }
});
