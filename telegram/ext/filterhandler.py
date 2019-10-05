#!/usr/bin/env python
#
# A library that provides a Python interface to the Telegram Bot API
# Copyright (C) 2015-2018
# Leandro Toledo de Souza <devs@python-telegram-bot.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser Public License for more details.
#
# You should have received a copy of the GNU Lesser Public License
# along with this program.  If not, see [http://www.gnu.org/licenses/].
"""This module contains the FilterHandler class."""

from telegram import Update
from .handler import Handler


class FilterHandler(Handler):
    """Handler class to handle telegram updates.

    Attributes:
        filters (:obj:`Filter`): Only allow updates with these Filters. See
            :mod:`telegram.ext.filters` for a full list of all available filters.
        callback (:obj:`callable`): The callback function for this handler.

    Args:
        filters (:class:`telegram.ext.BaseFilter`, optional): A filter inheriting from
            :class:`telegram.ext.filters.BaseFilter`. Standard filters can be found in
            :class:`telegram.ext.filters.Filters`. Filters can be combined using bitwise
            operators (& for and, | for or, ~ for not).
        callback (:obj:`callable`): The callback function for this handler. Will be called when
            :attr:`check_update` has determined that an update should be processed by this handler.
            Callback signature for context based API:

            ``def callback(update: Update, context: CallbackContext)``

            The return value of the callback is usually ignored except for the special case of
            :class:`telegram.ext.ConversationHandler`.

    Raises:
        ValueError

    """

    def __init__(self,
                 filters,
                 callback):

        super(FilterHandler, self).__init__(callback)
        self.filters = filters

    def check_update(self, update):
        """Determines whether an update should be passed to this handlers :attr:`callback`.

        Args:
            update (:class:`telegram.Update`): Incoming telegram update.

        Returns:
            :obj:`bool`

        """
        if isinstance(update, Update):
            return self.filters(update)

    def collect_additional_context(self, context, update, dispatcher, check_result):
        if isinstance(check_result, dict):
            context.update(check_result)
