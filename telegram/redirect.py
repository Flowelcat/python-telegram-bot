"""This module contains an object that represents a Redirect."""

from telegram import (TelegramObject)


class Redirect(TelegramObject):
    """
    This object contains information about a redirect.

    Attributes:
        id (:obj:`str`): Unique redirect identifier.
        url (:obj:`str`): Redirect url.

    Args:
        id (:obj:`str`): Unique redirect identifier.
        url (:obj:`str`): Redirect url.

    """

    def __init__(self, id, url, chat, from_user, **kwargs):
        self.id = id
        self.url = url
        self.chat = chat
        self.from_user = from_user

        self._id_attrs = (self.id,)
