from django.urls import path

from .views import CapView, OwnerView, UnknownView, UnmappedView

urlpatterns = [
    path("owner/", OwnerView.as_view(), name="owner"),
    path("unknown/", UnknownView.as_view(), name="unknown"),
    path("unmapped/", UnmappedView.as_view(), name="unmapped"),
    path("cap/", CapView.as_view(), name="cap"),
]
