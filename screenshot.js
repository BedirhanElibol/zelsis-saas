const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('http://localhost:3000/dashboard');
  
  // Wait for the dashboard to load properly
  await page.waitForTimeout(3000);
  
  await page.screenshot({ path: 'C:\\Users\\Bedirhan\\.gemini\\antigravity\\brain\\6a3e6678-18db-4428-b26b-62905b5991c8\\scratch\\dashboard_screenshot.png', fullPage: true });
  
  await browser.close();
  console.log('Screenshot taken!');
})();
