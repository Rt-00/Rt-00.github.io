import { expect, test } from '@playwright/test';

test.describe('home', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('shows the terminal prompt and ls command', async ({ page }) => {
    await expect(page.locator('header')).toContainText('rt@blog');
    await expect(page.locator('main')).toContainText('rt@blog:~$ ls -l posts/');
    await expect(page.locator('footer')).toContainText('rt@blog:~$');
  });

  test('lists published posts grouped by year with lang and tags', async ({ page }) => {
    const row = page.getByRole('listitem').filter({ hasText: 'Bits + context:' });
    await expect(row).toContainText('[en]');
    await expect(row).toContainText('#csapp');
    await expect(row.getByRole('link', { name: /Bits \+ context:/ })).toHaveAttribute(
      'href',
      '/posts/csapp-1-1-bits-and-context/',
    );
    await expect(page.getByRole('heading', { name: '2026' })).toBeVisible();
  });

  test('lists the most recent post first', async ({ page }) => {
    const first = page.locator('main').getByRole('listitem').first();
    await expect(first.locator('a[href^="/posts/"]')).toHaveAttribute(
      'href',
      /\/posts\/hc-flashback\//,
    );
  });

  test('hides drafts in production builds', async ({ page }) => {
    await expect(page.locator('main')).not.toContainText('Draft example');
  });
});

test.describe('theme', () => {
  test('follows the system preference', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/');
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bg).toBe('rgb(0, 0, 0)');
  });

  test('toggle switches and persists across navigation', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/');
    await page.getByRole('button', { name: /theme/i }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bg).toBe('rgb(255, 255, 255)');
  });
});
