"""Screenshots for README (synthetic demo). Run the panel in demo mode, then: python3 tools/screenshots.py"""
import asyncio
import os
from playwright.async_api import async_playwright

URL = os.environ.get("ZASLON_URL", "http://127.0.0.1:8585")
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "screenshots")


async def main():
    os.makedirs(OUT, exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        await pg.goto(URL)
        await pg.wait_for_timeout(500)
        await pg.click("#btn-refresh-all")
        await pg.wait_for_timeout(2500)
        await pg.evaluate("document.querySelectorAll('.toast').forEach(t => t.remove())")
        await pg.screenshot(path=f"{OUT}/overview.png", full_page=True)
        hosts = dict(await pg.evaluate("fetch('/api/hosts').then(r=>r.json()).then(d=>d.hosts.map(h=>[h.name,h.id]))"))

        async def shot(host, sub, name, full=False, prep=None):
            await pg.goto(f"{URL}/#/h/{hosts[host]}/{sub}")
            await pg.wait_for_timeout(900)
            if prep:
                await prep()
            await pg.evaluate("document.querySelectorAll('.toast').forEach(t => t.remove())")
            await pg.screenshot(path=f"{OUT}/{name}.png", full_page=full)

        await shot("gateway-pi", "summary", "host-summary")
        await shot("gateway-pi", "ports", "ports")
        await shot("nas", "zones", "zones")
        await shot("nas", "selinux", "selinux")
        await shot("gateway-pi", "iptables", "iptables")

        async def queue():
            await pg.click("text=Никто не слушает")
            await pg.wait_for_timeout(200)
            btns = pg.locator("#ports-tbody button:has-text('Закрыть')")
            for i in range(3):
                await btns.nth(i).click()
                await pg.wait_for_timeout(150)
            await pg.click("#queue-bar >> text=Применить")
            await pg.wait_for_timeout(400)
        await shot("monitoring", "ports", "apply-review", prep=queue)
        await pg.keyboard.press("Escape")
        await b.close()


asyncio.run(main())
