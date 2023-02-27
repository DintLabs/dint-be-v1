from abc import ABC, abstractmethod


class StoriesBaseService(ABC):

    @abstractmethod
    def get_stories(self):
        """ Abstarct method for User Log in """
        pass