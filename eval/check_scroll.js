const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch({ headless: 'new' });
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:5173', { waitUntil: 'networkidle0' });

    // Wait for the incident table to appear
    await page.waitForSelector('tbody tr', { timeout: 10000 });
    
    // Click the first incident row
    const row = await page.$('tbody tr');
    if (row) await row.click();
    await page.waitForTimeout(1000);

    // Get the scroll container (it's the 1/2 width container that has the Incident Details)
    // We added id="incident-detail-panel" to it.
    const scrollContainer = await page.$('#incident-detail-panel');
    if (!scrollContainer) {
        console.log("Could not find incident detail panel");
        process.exit(1);
    }

    // Scroll down by 300
    await page.evaluate(el => el.scrollTop = 300, scrollContainer);
    
    const beforeScroll = await page.evaluate(el => el.scrollTop, scrollContainer);
    console.log(`scrollTop before: ${beforeScroll}`);
    
    // Wait 5 seconds to let polling happen
    await page.waitForTimeout(5000);
    
    const afterScroll = await page.evaluate(el => el.scrollTop, scrollContainer);
    console.log(`scrollTop after: ${afterScroll}`);
    
    await browser.close();
})();
