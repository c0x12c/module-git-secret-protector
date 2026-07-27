class UnsupportedFormatError(ValueError):
    """Raised when a blob or key uses a wire/scheme version this client does not
    understand (newer than supported), as opposed to a transient failure like a
    cache miss. The git filter treats this as fail-closed: abort rather than pass
    ciphertext through as if it were content.

    Subclasses ValueError so existing `except ValueError` decrypt paths keep working.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
