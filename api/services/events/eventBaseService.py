from abc import ABC, abstractmethod


class EventBaseService(ABC):

    @abstractmethod
    def create_event(self):
        """ Abstract method to get all roles """
        pass

    @abstractmethod
    def update_event(self):
        """
        Abstract method to create Role
        """
        pass


    @abstractmethod
    def get_event_by_id(self):
        """
        Abstract method for deletion of Role
        """
        pass


    @abstractmethod
    def get_events_by_user(self):
        """
        Abstract method for Role Name and Full Name updation
        """
        pass

    @abstractmethod
    def delete_event(self):
        """
        Abstract method for Retrieving of Role
        """
        pass

    @abstractmethod
    def get_all_event(self):
        """
        Abstract method for Retrieving of Role
        """
        pass