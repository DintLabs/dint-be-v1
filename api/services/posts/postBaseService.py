from abc import ABC, abstractmethod


class PostsBaseService(ABC):

    @abstractmethod
    def get_post_list(self):
        """ Abstract method to get all roles """
        pass

    @abstractmethod
    def create_post(self):
        """
        Abstract method to create Role
        """
        pass


    @abstractmethod
    def delete_post(self):
        """
        Abstract method for deletion of Role
        """
        pass


    @abstractmethod
    def update_post(self):
        """
        Abstract method for Role Name and Full Name updation
        """
        pass

    @abstractmethod
    def get_post(self):
        """
        Abstract method for Retrieving of Role
        """
        pass
