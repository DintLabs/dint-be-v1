from abc import ABC, abstractmethod


class ChatBaseService(ABC):

    # @abstractmethod
    # def get_message_list(self):
    #     """ Abstract method to get all roles """
    #     pass

    @abstractmethod
    def create_message(self):
        """
        Abstract method to create Role
        """
        pass


    # @abstractmethod
    # def delete_message(self):
    #     """
    #     Abstract method for deletion of Role
    #     """
    #     pass

    @abstractmethod
    def update_message(self):
        """
        Abstract method for deletion of Role
        """
        pass

    # @abstractmethod
    # def get_message_by_id(self):
    #     """
    #     Abstract method for deletion of Role
    #     """
    #     pass

    # @abstractmethod
    # def get_chat_screen_preview(self):
    #     """
    #     Abstract method for deletion of Role
    #     """
    #     pass

