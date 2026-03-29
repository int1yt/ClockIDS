from django.urls import path
from . import views

urlpatterns = [
    path('read_csv', views.read_csv),
    path('dashboard', views.dashboard),
    path('classify_attack_json', views.classify_attack_json),
    path('simulate_attack_and_predict', views.simulate_attack_and_predict),
    path('start_monitor', views.start_monitor),
    path('poll_monitor', views.poll_monitor),
]