from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse


def staff_only(view):
    """Plain-Django staff gate: no DRF permission_classes to read."""

    @login_required(login_url="/login/")
    def guarded(request, *args, **kwargs):
        if not (request.user.is_active and request.user.is_staff):
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return guarded


@staff_only
def decorated(request):
    return HttpResponse("staff")


class HasWidgetWrite(BasePermission):
    """Control permission whose name maps to the widget.write capability."""

    message = "widget.write required"

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)


class HasWidgetWriteOrReadOnly(BasePermission):
    """Reads are public; writes require the widget.write capability."""

    write_capability = "widget.write"

    def has_permission(self, request, view):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        return bool(request.user and request.user.is_authenticated)


class PublicView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"scope": "public"})


class GatedView(APIView):
    permission_classes = [HasWidgetWriteOrReadOnly]

    def get(self, request):
        return Response({"scope": "gated"})

    def post(self, request):
        return Response({"scope": "gated"})


class CapView(APIView):
    permission_classes = [HasWidgetWrite]

    def get(self, request):
        return Response({"scope": "capability"})


class WidgetViewSet(ViewSet):
    permission_classes = [AllowAny]

    def list(self, request):
        return Response([])

    @action(detail=True, methods=["post"], url_path="poke")
    def poke(self, request, pk=None):
        return Response({"poked": pk})
