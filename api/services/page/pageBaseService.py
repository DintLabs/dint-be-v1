from abc import ABC, abstractmethod


class PageBaseService(ABC):

    @abstractmethod
    def get_page_list(self):
        """ Abstract method to get all roles """
        pass

    @abstractmethod
    def create_page(self):
        """
        Abstract method to create Role
        """
        pass


    @abstractmethod
    def delete_page(self):
        """
        Abstract method for deletion of Role
        """
        pass


    @abstractmethod
    def update_page(self):
        """
        Abstract method for Role Name and Full Name updation
        """
        pass

    @abstractmethod
    def get_page(self):
        """
        Abstract method for Retrieving of Role
        """
        pass
