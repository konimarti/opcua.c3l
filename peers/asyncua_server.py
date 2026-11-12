#!/usr/bin/env python3
"""A small OPC UA test server built with asyncua (run only; asyncua is LGPL and is neither copied nor linked).

Usage: asyncua_server.py [port] [peer.env path]

SecurityPolicy None, anonymous and user name logins (peter / peter123), the nodes the peer tests need, and an Add method.
It writes the parameters of the peer tests (peers/peer.env format) to the given file and prints them.
"""
import asyncio
import sys

from asyncua import Server, ua
from asyncua.common.methods import uamethod
from asyncua.crypto.permission_rules import User, UserRole


class Users:
    """User manager: anonymous and one user name / password pair."""

    def get_user(self, iserver, username=None, password=None, certificate=None):
        if username is None:
            return User(role=UserRole.Admin)
        if username == "peter" and password == "peter123":
            return User(role=UserRole.Admin)
        return None


@uamethod
def add(parent, a, b):
    return a + b


async def main(port, env_path):
    server = Server(user_manager=Users())
    await server.init()
    server.set_endpoint("opc.tcp://127.0.0.1:%d/" % port)
    server.set_server_name("opcua.c3l test server")
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    server.set_identity_tokens([ua.AnonymousIdentityToken, ua.UserNameIdentityToken])
    idx = await server.register_namespace("urn:opcua.c3l:test")
    objects = server.nodes.objects
    folder = await objects.add_folder(idx, "Test")
    int32 = await folder.add_variable(idx, "Int32", ua.Variant(42, ua.VariantType.Int32))
    double = await folder.add_variable(idx, "Double", ua.Variant(1.5, ua.VariantType.Double))
    string = await folder.add_variable(idx, "String", ua.Variant("hello", ua.VariantType.String))
    array = await folder.add_variable(idx, "Array", ua.Variant([1, 2, 3], ua.VariantType.Int32))
    for node in (int32, double, string, array):
        await node.set_writable()
    method = await objects.add_method(
        idx, "Add",
        add,
        [ua.VariantType.Int32, ua.VariantType.Int32],
        [ua.VariantType.Int32],
    )
    lines = [
        "OPCUA_PEER_URL=opc.tcp://127.0.0.1:%d/" % port,
        "OPCUA_USER=peter",
        "OPCUA_PASSWORD=peter123",
        "OPCUA_NODE_INT32=%s" % int32.nodeid.to_string(),
        "OPCUA_NODE_DOUBLE=%s" % double.nodeid.to_string(),
        "OPCUA_NODE_STRING=%s" % string.nodeid.to_string(),
        "OPCUA_NODE_ARRAY=%s" % array.nodeid.to_string(),
        "OPCUA_NODE_METHOD_OBJECT=%s" % objects.nodeid.to_string(),
        "OPCUA_NODE_METHOD=%s" % method.nodeid.to_string(),
        "OPCUA_METHOD_KIND=add",
    ]
    if env_path:
        with open(env_path, "w") as f:
            f.write("\n".join(lines) + "\n")
    print("\n".join(lines), flush=True)
    async with server:
        while True:
            await asyncio.sleep(3600)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4841
    env_path = sys.argv[2] if len(sys.argv) > 2 else None
    asyncio.run(main(port, env_path))
