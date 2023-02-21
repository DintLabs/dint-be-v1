from abc import ABC, abstractmethod


class PayoutsBaseService(ABC):

    @abstractmethod
    def request_payouts_by_token(self):
        """ Abstarct method for User Log in """
        pass