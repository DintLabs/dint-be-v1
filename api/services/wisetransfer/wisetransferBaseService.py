from abc import ABC, abstractmethod


class WiseTransferBaseService(ABC):

    @abstractmethod
    def create_quotes_by_token(self):
        """ Abstarct method for Create quotes for wise """
        pass