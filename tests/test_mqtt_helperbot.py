import asyncio
import bumper
import pytest

@pytest.mark.asyncio
async def test_helperbot_connects():
    address = ("127.0.0.1", 8885)
    server = bumper.MQTTServer(address, password_file="tests/passwd")
    await server.broker_coro()
    helperbot = bumper.MQTTHelperBot(address)
    await helperbot.start_helper_bot()
    assert helperbot.Client.session.transitions.state == "connected"
    await helperbot.Client.disconnect()
    await server.broker.shutdown()
