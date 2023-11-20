from __future__ import annotations
from discord.ext import commands
from discord import app_commands
from typing import Optional
import discord

class VirusTotal(commands.Cog, name="virustotal"):
    def __init__(self: VirusTotal, bot: commands.Bot) -> None:
        self._bot: commands.Bot = bot
        return

    @app_commands.command(
        name="ping",
        description="Generic ping command."
    )
    async def _ping(self: VirusTotal, interaction: discord.Interaction) -> None:
        await interaction.response.send_message("Pong!")
        return

async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(VirusTotal(bot))
    return

