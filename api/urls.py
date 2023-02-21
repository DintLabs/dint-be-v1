from django.urls import path, include
from .views import *
from rest_framework.routers import DefaultRouter

from django.urls import re_path

from chat import consumers

# websocket_urlpatterns = [
#     re_path(r'ws/auth/login', consumers.ChatConsumer.as_asgi()),
# ]

app_name = 'api'
routers = DefaultRouter()
routers.register('referral', UserReferralWalletModelViewSet, base_name='referral')
routers.register('tip-reference', UserTipReferenceModelViewSet, base_name='tip-reference')
routers.register('confine-user', confineUserModelViewSet, base_name='confine-user')
routers.register('user-list', UserCustomListsModelViewSet, base_name='user-list')
routers.register('add-member-in-list', UserCustomGroupMembersModelViewSet, base_name='add-member-in-list')

urlpatterns = [
    path('', include(routers.urls)),
    path('auth/login', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/sign-up/', SignupView.as_view(), name='auth-sign-up'),

    #user web3 wallet
    path('user/decrypt-wallet-token/', UserDecryptWalletTokenView.as_view(), name="decrypt-user-wallet-token"),
    path('user/wallet', UserWalletView.as_view(), name="get-user-wallet"),
    path('user/update-wallet-by-token/', UserWalletView.as_view(), name="update-user-wallet"),

    #user preferences
    path('user/get-user-preferences/', UserPreferencesView.as_view(), name="get-user-preferences"),
    path('user/update-user-preferences/', UserPreferencesView.as_view(), name="update-user-preferences"),

    #user bookmarks
    path('user/get-user-bookmarks/', UserBookmarksView.as_view(), name="get-user-bookmarks"),
    path('user/create-user-bookmarks/', UserBookmarksView.as_view(), name="create-user-bookmarks"),
    path('user/delete-user-bookmarks/<int:pk>/', UserBookmarksView.as_view(), name="delete-user-bookmarks"),

    # update user status
    path('user/update-status/', UserUpdateStatusView.as_view(),  name="update-user-status"),

    #OTP
    path('user/verify-otp/', VarifyOtpView.as_view(), name="verify-otp"),
    path('user/send-otp-to-old-user/', SendOtpForOldUser.as_view(), name="send-otp-to-old-user"),

    #profile
    path('user/get-profile-by-token/', ProfileView.as_view(), name="verify-otp"),
    path('user/get-page-profile-by-token/', PageProfileView.as_view(), name="verify-otp"),
    path('user/get-profile-by-username/', ProfileUsernameView.as_view(), name="verify-otp"),
    path('user/update-profile-by-token/', ProfileView.as_view(), name="verify-otp"),

    # user stories
    path('user/get-stories/',UserStoriesView.as_view(), name="get-stories"),
    path('user/get-stories-by-user/',UserStoriesByUserView.as_view(), name="get-stories-by-user"),
    path('user/create-stories/',UserStoriesView.as_view(), name="create-stories"),
    path('user/delete-stories/<int:pk>/', UserStoriesView.as_view(), name="delete-stories"),

    # USER SEND DINT
    path('user/withdraw-dint/', WithdrawDint.as_view(), name="withdraw-dint"),
    path('user/send-dint/', UserSendDint.as_view(), name="send-dint-by-id"),
    path('user/send-reward/', UserDintReward.as_view(), name="send-reward-by-token"),
    
    path('user/validate_referral_code/', ValidateUserReferral.as_view(), name="validate-user-referral"),
    path('user/add_referral_code/', AddReferralCode.as_view(), name="add_referral_code"),
    path('user/referral_code/', UserReferralCode.as_view(), name="user_referral_code"),
    path('user/track_ip_address/', TrackUserIpAddress.as_view(), name = "track_user_ip_address"),
    path('user/get_referral_id/', GetUserReferralId.as_view(), name="get_user_referral_id"),

    # suggestions to user
    path('user/get_suggestions/', UserSuggestions.as_view(), name = "get_suggestions"),
    #role
    path('role/get-all-roles/', RoleListView.as_view(), name="get-all-role"),
    path('role/create-role/', RoleCreateView.as_view(), name="create-role"),

    #uploadMedia
    path('upload/media/', UploadMediaView.as_view(), name="upload-media"),
    path('delete-media/<int:pk>/', DeleteMediaView.as_view(), name="delete-media"),

    #Posts
    path('posts/list/', ListCreateUpdateDeletePostView.as_view(), name="get-all-posts"),
    path('posts/pagination/list/', GetPostPaginationView.as_view(), name="get-all-posts"),
    path('posts/list_by_user_id/<int:pk>/', PostByUserIDView.as_view(), name="create-posts"),
    path('posts/pagination/list_by_user_id/<int:pk>/', PostPaginationByUserIDView.as_view(), name="pagination/list_by_user_id"),
    path('posts/create/', ListCreateUpdateDeletePostView.as_view(), name="create-posts"),
    path('posts/get/<int:pk>/', GetPostView.as_view(), name="create-posts"),
    path('posts/update/<int:pk>/', ListCreateUpdateDeletePostView.as_view(), name="create-posts"),
    path('posts/delete/<int:pk>/', ListCreateUpdateDeletePostView.as_view(), name="create-posts"),
    path('posts/list/page/<int:pk>/', PostPaginationByPageIDView.as_view(), name="get-all-posts/list_by_page_id"),
    path('posts/fetch-post-counts/<int:user_name>/', GetPostCountsByUserIDView.as_view(), name="create-posts"),
    path('posts/like/', LikePostView.as_view(), name="create-posts"),
    path('posts/comment/', CommentPostView.as_view(), name="comment-posts"),
    path('posts/unlike/', UnLikePostView.as_view(), name="unlike-posts"),
    path('posts/send_payment/', PostPayment.as_view(), name="send_payment"),
    path('posts/unlock_post/', PostPayment.as_view(), name="post_unlock"),

    #Events
    path('events/list/', ListCreateUpdateDeleteEventView.as_view(), name="get-all-posts"),
    path('events/list_by_user_id/<int:pk>/', GetEventByUserIDView.as_view(), name="create-posts"),
    path('events/create/', ListCreateUpdateDeleteEventView.as_view(), name="create-posts"),
    path('events/get/<int:pk>/', GetEventByIDView.as_view(), name="create-posts"),
    path('events/update/<int:pk>/', ListCreateUpdateDeleteEventView.as_view(), name="create-posts"),
    path('events/delete/<int:pk>/', ListCreateUpdateDeleteEventView.as_view(), name="create-posts"),

    #Venues
    path('venue/list/', ListCreateUpdateDeleteVenueView.as_view(), name="get-all-posts"),
    path('venue/list_by_user_id/<int:pk>/', GetVenueByUserIDView.as_view(), name="create-posts"),
    path('venue/create/', ListCreateUpdateDeleteVenueView.as_view(), name="create-posts"),
    path('venue/get/<int:pk>/', GetVenueByIDView.as_view(), name="create-posts"),
    path('venue/update/<int:pk>/', ListCreateUpdateDeleteVenueView.as_view(), name="create-posts"),
    path('venue/delete/<int:pk>/', ListCreateUpdateDeleteVenueView.as_view(), name="create-posts"),

    #Lounge
    path('lounge/pagination/list/', GetLoungePostPaginationView.as_view(), name="get-all-posts"),
    path('lounge/fetch-post-counts/', GetTotalPostCountsView.as_view(), name="create-posts"),

    #Subscription
    path('subscription-tier/list-by-user/', ListCreateUpdateDeleteSubscriptionTierView.as_view(), name="get-all-posts"),
    path('subscription-tier/create/', ListCreateUpdateDeleteSubscriptionTierView.as_view(), name="create-posts"),
    path('subscription-tier/get/<int:pk>/', GetSubscriptionTierView.as_view(), name="create-posts"),
    path('subscription-tier/update/<int:pk>/', ListCreateUpdateDeleteSubscriptionTierView.as_view(), name="create-posts"),
    path('subscription-tier/delete/<int:pk>/', ListCreateUpdateDeleteSubscriptionTierView.as_view(), name="create-posts"),
    path('subscription/active/list-by-user/', SubscriptionView.as_view(), name="create-posts"),
    path('subscription/all/list-by-user/', GetActiveSubscriptionView.as_view(), name="create-posts"),
    path('subscription/subscribe/', SubscriptionView.as_view(), name="create-posts"),
    path('subscription/unsubscribe/<int:pk>/', SubscriptionView.as_view(), name="create-posts"),
    path('subscription/promotion-campaign/list-by-user/', ListCreateUpdateDeletePromotionCampaignView.as_view(), name="get-all-posts"),
    path('subscription/promotion-campaign/create/', ListCreateUpdateDeletePromotionCampaignView.as_view(), name="create-posts"),
    path('subscription/promotion-campaign/get/<int:pk>/', GetPromotionCampaignView.as_view(), name="create-posts"),
    path('subscription/promotion-campaign/update/<int:pk>/', ListCreateUpdateDeletePromotionCampaignView.as_view(), name="create-posts"),
    path('subscription/promotion-campaign/delete/<int:pk>/', ListCreateUpdateDeletePromotionCampaignView.as_view(), name="create-posts"),
    path('subscription/free-trial/list-by-user/', ListCreateUpdateDeleteFreeTrialView.as_view(), name="get-all-posts"),
    path('subscription/free-trial/create/', ListCreateUpdateDeleteFreeTrialView.as_view(), name="create-posts"),
    path('subscription/free-trial/get/<int:pk>/', GetFreeTrialView.as_view(), name="create-posts"),
    path('subscription/free-trial/update/<int:pk>/', ListCreateUpdateDeleteFreeTrialView.as_view(), name="create-posts"),
    path('subscription/free-trial/delete/<int:pk>/', ListCreateUpdateDeleteFreeTrialView.as_view(), name="create-posts"),
    path('subscription/get-subscriber-by-page-id/<int:pk>/', GetSubscribersByPageView.as_view(), name="create-posts"),
    path('subscription/get-pages-by-subscriber-id/<int:pk>/', GetPageBySubscriberIDView.as_view(), name="create-posts"),

    #Chat
    path('chat/get-chat-by-user/<int:pk>/', ListCreateUpdateDeleteMessageView.as_view(), name="create-posts"),
    path('chat/get-chat-by-user-in-chunks/<int:pk>/', ListMessageChunksView.as_view(), name="create-posts"),
    path('chat/create-message/', ListCreateUpdateDeleteMessageView.as_view(), name="create-posts"),
    path('chat/update-message/<int:pk>/', ListCreateUpdateDeleteMessageView.as_view(), name="create-posts"),
    path('chat/delete-message/<int:pk>/', ListCreateUpdateDeleteMessageView.as_view(), name="create-posts"),
    path('chat/get-message/<int:pk>/', GetMessageByIDView.as_view(), name="create-posts"),
    path('chat/get-chat-list-by-token/', GetChatListByTokenView.as_view(), name="create-posts"),
    path('chat/search_user/', SearchUserView.as_view(), name="create-posts"),
    path('chat/create-notification/', ListCreateUpdateDeleteNotificationView.as_view(), name="create-notification"),
    path('chat/get-notification-by-user-in-chunks/<int:pk>/', ListNotificationsChunksView.as_view(), name="create-notification"),
    path('chat/get-unseen-message/', GetUnseenChatByUser.as_view(), name="unseen-chat"),
    #Page
    path('page/list/', ListCreateUpdateDeletePageView.as_view(), name="get-all-page"),
    path('page/pagination/list/', GetPagePaginationView.as_view(), name="get-all-page"),
    path('page/list_by_user_id/<int:pk>/', PageByUserIDView.as_view(), name="create-page"),
    path('page/pagination/list_by_user_id/<int:pk>/', PagePaginationByUserIDView.as_view(), name="create-page"),
    path('page/create/', ListCreateUpdateDeletePageView.as_view(), name="create-page"),
    path('page/get/<int:pk>/', GetPageView.as_view(), name="create-page"),
    path('page/update/<int:pk>/', ListCreateUpdateDeletePageView.as_view(), name="create-page"),
    path('page/delete/<int:pk>/', ListCreateUpdateDeletePageView.as_view(), name="create-page"),
    path('page/search/', SearchPageView.as_view(), name="create-page"),    
    path('page/get-by-page_name/<str:page_name>/', GetPageByPageNameView.as_view(), name="create-page"),
    path('page/check-user-name-availability/<str:user_name>/', CheckUsernameAvailabilityView.as_view(), name="create-page"),

    #Connection
    path('connection/follow/<int:pk>/', FollowView.as_view(), name="create-page"),
    path('connection/unfollow/<int:pk>/', UnfollowView.as_view(), name="create-page"),
    path('connection/remove-follower-by-user-id/<int:pk>/', RemoveFollowerView.as_view(), name="create-page"),
    path('connection/get-follow-request-list/', GetFollowRequestList.as_view(), name="create-page"),
    path('connection/update-follow-request-status/<int:pk>/', UpdateFollowRequestView.as_view(), name="create-page"),
    path('connection/get-follower-list/', GetFollowerListView.as_view(), name="create-page"),
    path('connection/get-following-list/', GetFollowingListView.as_view(), name="create-page"),
    path('connection/delete-follow-request/<int:pk>/', DeleteFollowRequestView.as_view(), name="create-page"),
    path('connection/update-privacy-status/', UpdatePrivacyStatusView.as_view(), name="create-page"),
    path('stripe/', include('api.payments.urls')),
    path('search-user/', SearchAnyUserView.as_view(), name="search-user"),
    path('user/get-close-friends/', CloseFriendsView.as_view(), name="close-friend"),
    path('user/create-close-friends/', CloseFriendsView.as_view(), name="create-close-friend"),
    path('user/delete-close-friends/<int:pk>/', CloseFriendsView.as_view(), name="delete-close-friend"),

    #verify user identity
    path('user/verify_identity/', VerifyIdentity.as_view(), name="verify-identity"), 
    path('user/send_verification_email/<int:pk>/', SendVerificationEmail.as_view(), name="send_verification_email"),
    path('user/validate_verification_token/', ValidateVerificationtoken.as_view(), name="validate_verification_token"),

     #Wise Quotes
    path('wise/create-quotes/', WiseQuotesView.as_view(), name="create-quotes"),
    path('wise/get-quotes/', WiseQuotesView.as_view(), name="get-quotes"),

    # Wise Recepients
    path('wise/create-recipients/', WiseRecepientsView.as_view(), name="create-recipients"),
    path('wise/get-recipients/', WiseRecepientsView.as_view(), name="get-recipient-details"),
    path('wise/delete-recipient/<int:pk>/', WiseRecepientsView.as_view(), name="delete-recipients"),
    # path('user/update-recipient-account/<int:pk>/', ReceiptTransferWiseView.as_view(), name="update-transferwise-details"),
    # Wise Transfers
    path('wise/create-transfer/', WiseTransferView.as_view(), name="create-wise-transfer"),
    # Wise Payments
    path('wise/create-payment/', WisePaymentView.as_view(), name="create-wise-payment"),

    # user bank accounts
    path('user/add_bank_accounts/', UserBankAccounts.as_view(), name="add_bank_accounts"),
    path('user/get_bank_accounts/', UserBankAccounts.as_view(), name="get_bank_accounts"),
    path('user/update_bank_account/<int:id>/', UserBankAccounts.as_view(), name="update_bank_accounts"),
    path('user/request_payouts/', UserPayouts.as_view(), name="add_payouts"),
    path('user/get_requested_payouts/', UserPayouts.as_view(), name="get_requested_payouts"),
    path('user/get_payouts_by_token/', UserPayoutsByToken.as_view(), name="get_payouts_by_token")
]

