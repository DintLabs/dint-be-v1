from abc import ABC, abstractmethod


class SubscriptionBaseService(ABC):

    @abstractmethod
    def create_tier(self):
        """ Abstract method to get all roles """
        pass

    @abstractmethod
    def update_tier(self):
        """
        Abstract method to create Role
        """
        pass


    @abstractmethod
    def get_tier_by_id(self):
        """
        Abstract method for deletion of Role
        """
        pass


    @abstractmethod
    def get_tier_by_user(self):
        """
        Abstract method for Role Name and Full Name updation
        """
        pass

    @abstractmethod
    def delete_tier(self):
        """
        Abstract method for Retrieving of Role
        """
        pass

    @abstractmethod
    def subscribe(self):
        """
        Abstract method for Role Name and Full Name updation
        """
        pass

    @abstractmethod
    def cancel_subscription(self):
        """
        Abstract method for Retrieving of Role
        """
        pass
