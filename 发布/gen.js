const puppeteer = require('puppeteer');
(async () => {
  const browser = await puppeteer.launch({headless: 'new'});
  const page = await browser.newPage();
  await page.goto('file://' + process.argv[2], {waitUntil: 'networkidle0'});
  await page.pdf({path: process.argv[3], format: 'A4'});
  await browser.close();
  console.log('Done');
})();
