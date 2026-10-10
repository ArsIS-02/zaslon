"""UI smoke test (Playwright). Run the panel in demo mode first:
   ZASLON_DATA=/tmp/zdata ZASLON_DEMO=1 uvicorn app.main:app --port 8585
   python3 tests/ui_smoke.py"""
import asyncio
import os
from playwright.async_api import async_playwright
URL = os.environ.get("ZASLON_URL", "http://127.0.0.1:8585")
OUT = os.environ.get("ZASLON_SHOTS", "/tmp/zaslon-shots")
async def main():
    os.makedirs(OUT, exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1440, "height": 950})
        errs = []
        pg.on("pageerror", lambda e: errs.append(f"pageerror: {e}"))
        pg.on("console", lambda m: errs.append(f"{m.type}: {m.text}") if m.type == "error" else None)
        await pg.goto(URL); await pg.wait_for_timeout(600)
        hosts = await pg.evaluate("fetch('/api/hosts').then(r=>r.json()).then(d=>d.hosts.map(h=>[h.id,h.name]))")
        hid = [h for h in hosts if h[1]=="monitoring"][0][0]
        await pg.goto(f"{URL}/#/h/{hid}/ports"); await pg.wait_for_timeout(1500)
        await pg.click("text=Никто не слушает"); await pg.wait_for_timeout(300)
        btns = pg.locator("#ports-tbody button:has-text('Закрыть')")
        await btns.nth(0).click(); await pg.wait_for_timeout(200)
        await btns.nth(1).click(); await pg.wait_for_timeout(300)
        await pg.screenshot(path=f"{OUT}/04-queue.png")
        await pg.click("#queue-bar >> text=Применить"); await pg.wait_for_timeout(400)
        await pg.screenshot(path=f"{OUT}/05-review.png")
        await pg.locator(".modal input[type=checkbox]").uncheck()
        await pg.click(".modal .ft >> text=Применить"); await pg.wait_for_timeout(2500)
        await pg.screenshot(path=f"{OUT}/06-result.png")
        await pg.click(".modal .ft >> text=Закрыть"); await pg.wait_for_timeout(500)
        await pg.screenshot(path=f"{OUT}/07-pending.png")
        await pg.click("#pending-bar >> text=Подтвердить"); await pg.wait_for_timeout(2000)
        await pg.goto(f"{URL}/#/h/{hid}/history"); await pg.wait_for_timeout(1200)
        await pg.screenshot(path=f"{OUT}/08-history.png")
        await pg.goto(f"{URL}/#/h/{hid}/zones"); await pg.wait_for_timeout(1000)
        await pg.screenshot(path=f"{OUT}/08b-zones.png")
        await pg.click("text=Добавить правило…"); await pg.wait_for_timeout(300)
        await pg.screenshot(path=f"{OUT}/09-rich.png")
        await pg.keyboard.press("Escape")
        await pg.click("button.tab.add"); await pg.wait_for_timeout(300)
        await pg.screenshot(path=f"{OUT}/10-addhost.png")
        print("\n".join(errs) or "no errors")
        await b.close()
asyncio.run(main())
