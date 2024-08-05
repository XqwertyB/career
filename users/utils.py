import requests
from django.utils.autoreload import logger
from rest_framework.exceptions import ValidationError


# def send_phone_notification(phone, code):
#     abonent_code = phone[3:5]
#     if int(abonent_code) in [97, 88, 90, 91, 99, 77, 95, 93, 94, 50, 20]:
#         try:
#             response = requests.get(
#                 f"https://portal.inhub.uz:8443/hunar?sn=8687&msisdn={phone}&message=Tasdiqlash kodi: {code}")
#             print(response)
#             return response
#         except Exception as e:
#             logger.error("Send message to user error: ", e)
#             logger.error('[97, 88, 90, 91, 99, 77, 95, 93, 94, 50, 20] error: {}'.format(e))
#     elif int(abonent_code) in [98, 33]:
#         try:
#             return requests.get(
#                 f"https://portal.inhub.uz:8443/hunar?sn=6500&msisdn={phone}&message=Tasdiqlash kodi: {code}")
#         except Exception as e:
#             logger.error("Send message to user error: ", e)
#             logger.error('[98, 33] error: {}'.format(e))
#     else:
#         data = {
#             'succes': False,
#             "message": f"Code {abonent_code} is not supported!",
#         }
#         raise ValidationError(data)
