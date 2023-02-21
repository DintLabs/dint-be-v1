from abc import ABC, abstractmethod


class BankAccountsBaseService(ABC):

    @abstractmethod
    def add_bank_accounts_by_token(self):
        """ Abstarct method for User Log in """
        pass