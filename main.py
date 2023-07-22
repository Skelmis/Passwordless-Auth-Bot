import asyncio
import logging
import os

import cooldowns
import disnake
import httpx
from Crypto.Cipher import PKCS1_OAEP
from alaric import EncryptedDocument, AQ
from alaric.comparison import EQ
from alaric.encryption import EncryptedFields, AutomaticHashedFields, HQF
from alaric.logical import AND
from disnake.ext import commands
from motor.motor_asyncio import AsyncIOMotorClient

from cooldown_bucket import InteractionBucket
from models import User

logging.basicConfig(
    format="%(levelname)-7s | %(asctime)s | %(message)s",
    datefmt="%I:%M:%S %p %d/%m/%Y",
    level=logging.INFO,
)
gateway_logger = logging.getLogger("disnake.gateway")
gateway_logger.setLevel(logging.WARNING)
client_logger = logging.getLogger("disnake.client")
client_logger.setLevel(logging.WARNING)
http_logger = logging.getLogger("disnake.http")
http_logger.setLevel(logging.WARNING)
log = logging.getLogger(__name__)

request_proto = os.environ.get("PROTO", "https")


async def main():
    bot = commands.InteractionBot()
    db_client = AsyncIOMotorClient(os.environ.get("MONGO_URL"))
    database = db_client["passwordless_platform_bot"]
    user_collection: EncryptedDocument = EncryptedDocument(
        database,
        "users",
        converter=User,
        encryption_key=bytes.fromhex(os.environ.get("AES_KEY")),
        automatic_hashed_fields=AutomaticHashedFields(
            "username", "base_domain", "registered_for"
        ),
        encrypted_fields=EncryptedFields(
            "public_key", "private_key", "username", "base_domain", "registered_for"
        ),
    )

    @bot.event
    async def on_ready():
        log.info("Bot is ready")

    @bot.slash_command()
    @cooldowns.cooldown(1, 3, bucket=InteractionBucket.author)
    async def logins(interaction: disnake.CommandInteraction):
        """View all of your possible logins."""
        user_models = await user_collection.find_many(
            AQ(HQF(EQ("registered_for_hashed", interaction.author.id)))
        )
        description = "\n".join(
            f"**{u.base_domain}**: `{u.username}`" for u in user_models
        )
        embed = disnake.Embed(
            title=f"Logins for {interaction.author}", description=description
        )
        await interaction.send(embed=embed, ephemeral=True)

    @bot.slash_command()
    @cooldowns.cooldown(1, 3, bucket=InteractionBucket.author)
    async def register(
        interaction: disnake.CommandInteraction,
        username: str = commands.Param(description="Your username on the site."),
        base_domain: str = commands.Param(
            description="The domain you wish to sign up to. For example, fire.skelmis.co.nz"
        ),
    ):
        """Register auth for a site."""
        await interaction.response.defer(ephemeral=True, with_message=True)
        base_domain = base_domain.rstrip("/")

        user_already_exists = await user_collection.find(
            AQ(
                AND(
                    HQF(EQ("username_hashed", username)),
                    HQF(EQ("base_domain_hashed", base_domain)),
                )
            )
        )
        if user_already_exists:
            return await interaction.send(
                "A user already exists for this site with this name.", ephemeral=True
            )

        async with httpx.AsyncClient() as client:
            user = User.new(username, base_domain, interaction.author.id)
            r_1: httpx.Response = await client.post(
                f"{request_proto}://{base_domain}/register",
                json={
                    "username": user.username,
                    "public_key": user.public_key_str,
                },
            )
            if r_1.status_code != 201:
                log.info(
                    "%s(%s) failed to register to %s with error code %s and content %s",
                    interaction.author,
                    interaction.author.id,
                    base_domain,
                    r_1.status_code,
                    r_1.content,
                )
                return await interaction.send("Something went wrong.", ephemeral=True)

            await user_collection.insert(user)
            log.info(
                "%s(%s) created user %s on site %s",
                interaction.author,
                interaction.author.id,
                user.username,
                user.base_domain,
            )
            await interaction.send("User created.", ephemeral=True)

    @bot.slash_command()
    @cooldowns.cooldown(1, 3, bucket=InteractionBucket.author)
    async def login(
        interaction: disnake.CommandInteraction,
        username: str,
        code: str = commands.Param(
            description="The code provided to you by the website your trying to auth to."
        ),
    ):
        """Login to a site"""
        await interaction.response.defer(ephemeral=True, with_message=True)
        user_model: User = await user_collection.find(
            AQ(
                AND(
                    HQF(EQ("username_hashed", username)),
                    HQF(EQ("registered_for_hashed", interaction.author.id)),
                ),
            )
        )
        if not user_model:
            return await interaction.send(
                "No user exists with this username.", ephemeral=True
            )

        async with httpx.AsyncClient() as client:
            url = f"{request_proto}://{user_model.base_domain}/login/{user_model.username}/challenge?code={code}"
            r_1: httpx.Response = await client.post(url)
            if r_1.status_code != 200:
                log.error(
                    "%s(%s) failed to login to %s with status code %s and response %s",
                    interaction.author,
                    interaction.author.id,
                    user_model.base_domain,
                    r_1.status_code,
                    r_1.content,
                )
                return await interaction.send("Something went wrong.", ephemeral=True)

            r_2 = await client.get(
                f"{request_proto}://{user_model.base_domain}/public_key"
            )
            if r_2.status_code != 200:
                log.error("Failed to fetch public key for %s", user_model.base_domain)
                return await interaction.send("Something went wrong.", ephemeral=True)

            server_public_key = User.key_from_str(r_2.json()["server_public_key"])

            data = r_1.json()
            expected_value = bytes.fromhex(data["expected_value"])
            c_d = PKCS1_OAEP.new(user_model.private_key)
            data_d = c_d.decrypt(expected_value)

            encryptor = PKCS1_OAEP.new(server_public_key)
            send_value = encryptor.encrypt(data_d)
            r_3 = await client.post(
                f"{request_proto}://{user_model.base_domain}/login/{user_model.username}/followup",
                json={"expected_value": send_value.hex()},
            )
            if r_3.status_code != 204:
                log.error(
                    "%s(%s) followup had response code %s with request text %s",
                    interaction.author,
                    interaction.author.id,
                    r_3.status_code,
                    r_3.content,
                )
                return await interaction.send("Something went wrong.", ephemeral=True)

    @login.autocomplete("username")
    async def username_autocomplete(
        interaction: disnake.CommandInteraction, user_input: str
    ):
        entries = await user_collection.find_many(
            AQ(HQF(EQ("registered_for_hashed", interaction.author.id)))
        )
        usernames = [u.username for u in entries]
        return [v for v in usernames if user_input.lower() in v.lower()]

    await bot.start(os.environ.get("TOKEN"))


asyncio.run(main())
