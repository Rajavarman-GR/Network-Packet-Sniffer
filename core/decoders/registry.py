"""Registry for independent packet protocol decoders."""


class DecoderRegistry:
    def __init__(self):
        self._decoders = {}

    def register(self, decoder, replace=False):
        name = getattr(decoder, "name", "")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("A decoder must have a non-empty name.")
        key = name.casefold()
        if key in self._decoders and not replace:
            raise ValueError("A decoder named {!r} is already registered.".format(name))
        if not callable(getattr(decoder, "applies", None)) or not callable(
            getattr(decoder, "decode", None)
        ):
            raise TypeError("A decoder must implement applies() and decode().")
        self._decoders[key] = decoder
        return decoder

    def get(self, name):
        return self._decoders.get(str(name).casefold())

    def decoders(self):
        return tuple(sorted(self._decoders.values(), key=lambda item: (-item.priority, item.name)))

    def matching(self, packet, payload):
        matches = []
        for decoder in self.decoders():
            try:
                if decoder.applies(packet, payload):
                    matches.append(decoder)
            except (AttributeError, TypeError, ValueError, IndexError):
                continue
        return tuple(matches)

    def detect(self, packet, payload):
        matches = self.matching(packet, payload)
        return matches[0] if matches else None
