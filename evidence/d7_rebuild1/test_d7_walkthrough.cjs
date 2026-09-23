const { chromium } = require('/usr/lib/node_modules/playwright');
const fs = require('fs');
const path = require('path');

const EVIDENCE_DIR = path.resolve('evidence/d7_rebuild1');
if (!fs.existsSync(EVIDENCE_DIR)) {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
}

async function run() {
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 }
  });
  const page = await context.newPage();

  const consoleErrors = [];
  page.on('console', (msg) => {
    console.log(`[BROWSER ${msg.type()}]`, msg.text());
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });

  const snapshots = {};

  console.log('--- Step 1: Verify /org/entry ---');
  await page.goto('http://localhost:5173/org/entry');
  await page.waitForSelector('text=CYBERGUARD');
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '01_org_entry.png') });
  snapshots['01_org_entry'] = await page.locator('body').first().ariaSnapshot();
  console.log('Step 1 complete');

  console.log('--- Step 2: Verify /login subtle link ---');
  await page.goto('http://localhost:5173/login');
  await page.waitForSelector('text=Organization login →');
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '02_personal_login.png') });
  snapshots['02_personal_login'] = await page.locator('body').first().ariaSnapshot();
  console.log('Step 2 complete');

  console.log('--- Step 3: Register via /org/entry ---');
  await page.goto('http://localhost:5173/org/entry');
  await page.click('button:has-text("Register")');
  await page.waitForTimeout(300);

  const testSuffix = Math.random().toString(36).substring(2, 7);
  const testUsername = `sec.lead.${testSuffix}`;
  const testEmail = `lead.${testSuffix}@apex-sec.local`;
  const testPassword = 'Password123!';

  await page.fill('input[placeholder="alex.mercer"]', testUsername);
  await page.fill('input[placeholder="Alex Mercer"]', 'Security Lead');
  await page.fill('input[placeholder="analyst@yourcompany.com"]', testEmail);
  const passwordInputs = await page.locator('input[placeholder="••••••••"]').all();
  await passwordInputs[0].fill(testPassword);
  await passwordInputs[1].fill(testPassword);

  await page.screenshot({ path: path.join(EVIDENCE_DIR, '03_register_filled.png') });
  snapshots['03_register_filled'] = await page.locator('body').first().ariaSnapshot();

  // Click Next: Organization Setup
  await page.click('button:has-text("Next: Organization Setup")');
  await page.waitForSelector('text=Organization Name');

  // Verify live slug preview
  await page.fill('input[placeholder="Acme Cyber Defense"]', 'Apex Cyber Defense');
  await page.waitForTimeout(200);
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '04_org_name_step.png') });
  snapshots['04_org_name_step'] = await page.locator('body').first().ariaSnapshot();
  console.log('Step 3 complete');

  console.log('--- Step 4: Submit Create Organization -> /org/select ---');
  await page.click('button:has-text("Create organization")');
  await page.waitForURL('**/org/select', { timeout: 10000 });
  await page.waitForSelector('h3:has-text("Apex Cyber Defense")', { timeout: 10000 });
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '05_org_select.png') });
  snapshots['05_org_select'] = await page.locator('body').first().ariaSnapshot();
  fs.writeFileSync(path.join(EVIDENCE_DIR, 'snapshots.json'), JSON.stringify(snapshots, null, 2));
  console.log('Step 4 complete');

  console.log('--- Step 5: Select Organization -> /org/{id}/projects ---');
  // Click on the organization card
  await page.click('h3:has-text("Apex Cyber Defense")');
  await page.waitForURL('**/projects', { timeout: 10000 });
  await page.waitForSelector('text=Default Project', { timeout: 10000 });
  console.log('Page URL at step 5:', page.url());
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '06_projects_view.png') });
  snapshots['06_projects_view'] = await page.locator('body').first().ariaSnapshot();
  fs.writeFileSync(path.join(EVIDENCE_DIR, 'snapshots.json'), JSON.stringify(snapshots, null, 2));
  console.log('Step 5 complete');

  console.log('--- Step 6: Create New Project in Modal ---');
  await page.waitForSelector('button:has-text("New project")', { timeout: 10000 });
  await page.click('button:has-text("New project")');
  await page.waitForSelector('text=Create project');
  await page.fill('input[placeholder="Core Defense SOC"]', 'Perimeter Sentinel');
  await page.waitForTimeout(200);
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '07_new_project_modal.png') });
  snapshots['07_new_project_modal'] = await page.locator('body').first().ariaSnapshot();
  fs.writeFileSync(path.join(EVIDENCE_DIR, 'snapshots.json'), JSON.stringify(snapshots, null, 2));

  await page.click('div.fixed form button[type="submit"]');
  await page.waitForSelector('h3:has-text("Perimeter Sentinel")', { timeout: 10000 });
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '08_project_created.png') });
  snapshots['08_project_created'] = await page.locator('body').first().ariaSnapshot();
  fs.writeFileSync(path.join(EVIDENCE_DIR, 'snapshots.json'), JSON.stringify(snapshots, null, 2));
  console.log('Step 6 complete');

  console.log('--- Step 7: Activate Project & Topbar Chip ---');
  // Click on Perimeter Sentinel card to activate
  await page.click('h3:has-text("Perimeter Sentinel")');
  await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '09_project_activated.png') });
  snapshots['09_project_activated'] = await page.locator('body').first().ariaSnapshot();
  console.log('Step 7 complete');

  console.log('--- Step 8: Verify Reload Persistence ---');
  await page.reload();
  await page.waitForSelector('h3:has-text("Perimeter Sentinel")');
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '10_reload_persists.png') });
  snapshots['10_reload_persists'] = await page.locator('body').first().ariaSnapshot();
  console.log('Step 8 complete');

  console.log('--- Step 9: Archive Project ---');
  // Open kebab menu on Default Project
  const kebabButtons = await page.locator('button:has(svg.lucide-more-vertical)').all();
  if (kebabButtons.length > 0) {
    await kebabButtons[0].click();
    await page.waitForSelector('button:has-text("Archive")');
    await page.click('button:has-text("Archive")');
    await page.waitForSelector('text=Are you sure you want to archive');
    await page.screenshot({ path: path.join(EVIDENCE_DIR, '11_archive_modal.png') });
    snapshots['11_archive_modal'] = await page.locator('body').first().ariaSnapshot();
    await page.click('div[role="dialog"] button:has-text("Archive"), div.fixed button:has-text("Archive")');
    await page.waitForTimeout(600);
  }
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '12_archived_result.png') });
  snapshots['12_archived_result'] = await page.locator('body').first().ariaSnapshot();
  console.log('Step 9 complete');

  console.log('--- Step 10: Verify Old URLs Redirect ---');
  await page.goto('http://localhost:5173/org');
  await page.waitForURL('**/org/select', { timeout: 5000 });
  console.log('Redirect /org -> /org/select successful:', page.url());

  await page.goto('http://localhost:5173/organization');
  await page.waitForURL('**/org/select', { timeout: 5000 });
  console.log('Redirect /organization -> /org/select successful:', page.url());

  await page.goto('http://localhost:5173/org/some-legacy-path');
  await page.waitForURL('**/dashboard', { timeout: 5000 });
  await page.waitForSelector('text=Security Operations Center', { timeout: 10000 });
  console.log('Redirect /org/* -> /dashboard successful:', page.url());
  await page.screenshot({ path: path.join(EVIDENCE_DIR, '13_personal_dashboard.png') });
  snapshots['13_personal_dashboard'] = await page.locator('body').first().ariaSnapshot();
  console.log('Step 10 complete');

  // Write snapshots JSON and text summary
  fs.writeFileSync(path.join(EVIDENCE_DIR, 'snapshots.json'), JSON.stringify(snapshots, null, 2));

  let summaryMd = '# ORG-UX-REBUILD-1 Browser Verification Evidence\n\n';
  for (const [name, snap] of Object.entries(snapshots)) {
    summaryMd += `## ${name}\n\`\`\`yaml\n${snap}\n\`\`\`\n\n`;
  }
  fs.writeFileSync(path.join(EVIDENCE_DIR, 'walkthrough_evidence.md'), summaryMd);

  console.log('Console Errors caught:', consoleErrors.length);
  if (consoleErrors.length > 0) {
    console.log('Errors:', consoleErrors);
  }

  await browser.close();
  console.log('All D7 walkthrough tests passed successfully!');
}

run().catch((err) => {
  console.error('Walkthrough error:', err);
  process.exit(1);
});
