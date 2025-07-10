r = reader.events()
next(r)
e = next(r)

print(e.foo)

print(hex(id(e.skb)))

print(e.skb.ns.show())
print(e.skb.packet.show())
