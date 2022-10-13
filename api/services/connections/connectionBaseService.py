from abc import ABC, abstractmethod


class ConnectionBaseService(ABC):

    @abstractmethod
    def follow(self):
        """ Abstract method to get all roles """
        pass

   