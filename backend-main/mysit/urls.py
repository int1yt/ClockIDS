"""
URL configuration for mysit project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from django.http import HttpResponse
from django.shortcuts import redirect

urlpatterns = [
    path('ids/', include('ids.urls')),
    path('admin/', admin.site.urls),
    # 简单首页：避免浏览器访问 `/` 时出现 404
    path('', lambda request: redirect('/ids/read_csv')),
    # 浏览器默认会请求 `/favicon.ico`，这里做个占位避免 404
    path('favicon.ico', lambda request: HttpResponse(status=204)),
]
