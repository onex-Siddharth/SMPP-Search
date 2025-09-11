from django.urls import path
from . import views

urlpatterns = [
    path('', views.search_page, name='search_page'),
    path('upload/', views.upload_pcap, name='upload_pcap'),
    path('generate/', views.generate_csv, name='generate_csv'),
    path('download/csv/', views.download_csv, name='download_csv'),
    path('download/socket/<str:filename>/', views.download_socket_csv, name='download_socket_csv'),
    path('unmatched/<str:src_ip_port>/<str:dst_ip_port>/<str:pdu_type>/', views.unmatched_view, name='unmatched_view'),
]
