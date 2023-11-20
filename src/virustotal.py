from __future__ import annotations
from aiohttp import ClientSession
from discord.ext import commands
from hashlib import md5
from io import BytesIO
from os import getenv
from typing import Optional
import discord
import vt

class VirusTotal(commands.Cog, name="virustotal"):
    def __init__(self: VirusTotal, bot: commands.Bot) -> None:
        self._bot: commands.Bot = bot
        self._vt: vt.Client = vt.Client(str(getenv("VT_API_KEY")))
        return

    @discord.app_commands.command(
        name="ping",
        description="Generic ping command."
    )
    async def _ping(self: VirusTotal, interaction: discord.Interaction) -> None:
        await interaction.response.send_message("Pong!")
        return

    async def _scan_file(self: VirusTotal, file_url: str) -> vt.Object:
        file_bytes: bytes = await self._fetch_file(file_url)
        file_hash: str = md5(file_bytes).hexdigest()

        file: Optional[vt.Object] = None
        try:
            file = await self._vt.get_object_async(f"/files/{file_hash}")
        except vt.error.APIError:
            file_stream: BytesIO = BytesIO(file_bytes)
            file = await self._vt.scan_file_async(file_stream, wait_for_completion=True)

        return file

    async def _scan_url(self: VirusTotal, client: vt.Client, url: str) -> vt.Object:
        file: Optional[vt.Object] = None
        try:
            url_id: str = vt.url_id(url)
            file = await self._vt.get_object_async(f"/urls/{url_id}")
        except vt.error.APIError:
            file = await self._vt.scan_url_async(url, wait_for_completion=True)

        return file

    async def _fetch_file(self: VirusTotal, url: str) -> bytes:
        async with ClientSession() as session:
            async with session.get(url) as resp:
                return await resp.read()

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(VirusTotal(bot))
    return

