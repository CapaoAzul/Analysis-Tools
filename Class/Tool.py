
class Tool:
    __key = None

    def __init__(self, key):
        self.__key = key

    def set_key(self, key):
        self.__key = key

    def get_key(self):
        return self.__key
