from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView


class IsWidgetOwner(BasePermission):
    """OWNER derivation: name contains Owner, no capability."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)


class SomeMysteryPermission(BasePermission):
    """UNKNOWN derivation: unclassifiable permission name."""

    def has_permission(self, request, view):
        return True


class HasWidgetWrite(BasePermission):
    """Mapped CAPABILITY: widget.write is granted to admin+editor."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)


class HasWidgetDelete(BasePermission):
    """Unmapped CAPABILITY: widget.delete has no roles entry."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)


class OwnerView(APIView):
    permission_classes = [IsWidgetOwner]

    def get(self, request):
        return Response({"scope": "owner"})


class UnknownView(APIView):
    permission_classes = [SomeMysteryPermission]

    def get(self, request):
        return Response({"scope": "unknown"})


class UnmappedView(APIView):
    permission_classes = [HasWidgetDelete]

    def get(self, request):
        return Response({"scope": "unmapped"})


class CapView(APIView):
    permission_classes = [HasWidgetWrite]

    def get(self, request):
        return Response({"scope": "capability"})
