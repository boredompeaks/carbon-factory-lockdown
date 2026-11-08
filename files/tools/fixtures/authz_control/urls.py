from django.urls import path
from rest_framework.routers import SimpleRouter

from .views import CapView, GatedView, PublicView, WidgetViewSet, decorated

router = SimpleRouter()
router.register("widgets", WidgetViewSet, basename="widget")

urlpatterns = [
    path("public/", PublicView.as_view(), name="public"),
    path("gated/", GatedView.as_view(), name="gated"),
    path("cap/", CapView.as_view(), name="cap"),
    path("decorated/", decorated, name="decorated"),
] + router.urls
