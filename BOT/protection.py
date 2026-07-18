import time
from collections import defaultdict


class Protection:
    def __init__(self, bot, owner_id, get_admins_func, get_banned_func, add_banned_func):
        self.bot = bot
        self.owner_id = owner_id
        self.get_admins = get_admins_func
        self.get_banned = get_banned_func
        self.add_banned = add_banned_func

        self._user_commands = defaultdict(list)

        self.SPAM_LIMIT_10S = 5
        self.SPAM_LIMIT_60S = 10

    def is_privileged(self, user_id):
        return user_id == self.owner_id or user_id in self.get_admins()

    def is_banned(self, user_id):
        return user_id in self.get_banned()

    def check_spam(self, user_id):
        if self.is_privileged(user_id):
            return False

        if self.is_banned(user_id):
            return True

        now = time.time()
        self._user_commands[user_id].append(now)

        recent = [t for t in self._user_commands[user_id] if now - t < 60]
        self._user_commands[user_id] = recent

        last_10s = [t for t in recent if now - t < 10]

        if len(last_10s) > self.SPAM_LIMIT_10S or len(recent) > self.SPAM_LIMIT_60S:
            self.add_banned(user_id)
            return True

        return False
