from __future__ import annotations
from aiohttp import ClientSession
from discord.ext import commands
from hashlib import md5
from io import BytesIO
from os import getenv
from typing import Any, Optional
from validators import url
import discord
import vt

class VirusTotal(commands.Cog, name="virustotal"):
    def __init__(self: VirusTotal, bot: commands.Bot) -> None:
        self._bot: commands.Bot = bot
        self._vt: vt.Client = vt.Client(str(getenv("VT_API_KEY")))
        return

    @commands.Cog.listener()
    async def on_message(self: VirusTotal, message: discord.Message) -> None:
        # check the message for attachments and urls
        urls: list[str] = [word for word in message.content.split() if url(word)]
        if not (urls or message.attachments): return
        attachment_files: dict[str, bytes] = {file.filename: await file.read() for file in message.attachments}

        # query virustotal for attachments
        should_block: bool = False
        for fbytes in attachment_files.values():
            obj: vt.Object = await self._scan_file(fbytes=fbytes)
            should_block = self._is_blockable(obj)
            if should_block: break

        # query virustotal for urls if no attachments
        # were detected as suspicious
        if not should_block:
            for url_ in urls:
                obj: vt.Object = await self._scan_url(url_)
                should_block = self._is_blockable(obj)
                if should_block: break

        # delete the message and report the incident if anything
        # is flagged
        if should_block:
            await message.delete()
            await message.channel.send(f"Detected suspicious/malicious file in a message sent by {message.author.mention}.")

        return

    async def _scan_file(self: VirusTotal, *, url: str="", fbytes: bytes=b"") -> vt.Object:
        """
        @param file_bytes (bytes): The bytes of a file to scan.
        @return vt.Object: The scanned file.
        """
        if url:
            # load the file into ram and get the md5 hash of it
            fbytes = await self._fetch_file(url)
        file_hash: str = md5(fbytes).hexdigest()

        file: Optional[vt.Object] = None
        try:
            # check virustotal for the file if it's already present
            file = await self._vt.get_object_async(f"/files/{file_hash}")
        except vt.error.APIError:
            # if the file is not in virustotal, upload and scan it
            file_stream: BytesIO = BytesIO(file_bytes)
            file = await self._vt.scan_file_async(file_stream, wait_for_completion=True)

        return file

    async def _scan_url(self: VirusTotal, url: str) -> vt.Object:
        """
        @param url (str): The url to scan.
        @return vt.Object: The scanned url.
        """
        file: Optional[vt.Object] = None
        try:
            # query virustotal for the url
            url_id: str = vt.url_id(url)
            file = await self._vt.get_object_async(f"/urls/{url_id}")
        except vt.error.APIError:
            # scan the url manually if not present
            file = await self._vt.scan_url_async(url, wait_for_completion=True)

        return file

    def _is_blockable(self: VirusTotal, file: vt.Object) -> bool:
        """
        Determines if the file/url is malicious or suspicious, and therefore
        blockable.
        @param file (vt.Object): The scan report.
        @return bool: If the file/url is suspicious (20% of vendors need to agree), return True.

        """
        THRESHOLD: float = 0.2  # arbitrary
        scan_analysis: dict[str, Any] = file.last_analysis_stats

        noteworthy: int = 0
        total: int = 0
        for (classification, count) in scan_analysis.items():
            match classification:
                case "malicious":
                    noteworthy += (2 * count)
                case "suspicious":
                    noteworthy += count
                case _: pass
            if isinstance(count, int):
                total += count

        return (noteworthy / total) >= THRESHOLD

    async def _fetch_file(self: VirusTotal, url: str) -> bytes:
        async with ClientSession() as session:
            async with session.get(url) as resp:
                return await resp.read()

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(VirusTotal(bot))
    return

