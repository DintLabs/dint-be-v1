from abc import ABC, abstractmethod


class RoleBaseService(ABC):

    @abstractmethod
    def get_all_roles(self):
        """ Abstract method to get all roles """
        pass

    @abstractmethod
    def create(self):
        """
        Abstract method to create Role
        """
        pass

    # @abstractmethod
    # def assign_permission(self):
    #     """
    #     Abstract method for Assigning Permissions
    #     """
    #     pass

    @abstractmethod
    def delete(self):
        """
        Abstract method for deletion of Role
        """
        pass

    @abstractmethod
    def get_object(self):
        """
        Abstract method for getting Role instance
        """
        pass

    @abstractmethod
    def get_object_by_name(self):
        """
        Abstract method for getting Role instance by Name
        """
        pass

    @abstractmethod
    def role_pagination_list(self):
        """
        Abstract method for getting role list with pagination
        """
        pass

    @abstractmethod
    def update(self):
        """
        Abstract method for Role Name and Full Name updation
        """
        pass

    @abstractmethod
    def role_detail(self):
        """
        Abstract method for Retrieving of Role
        """
        pass
