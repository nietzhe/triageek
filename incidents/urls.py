from django.urls import path

from . import views

app_name = "incidents"

urlpatterns = [
    path("", views.incident_list, name="list"),
    path("new/", views.incident_create, name="create"),
    path("<int:pk>/", views.incident_detail, name="detail"),
    path("<int:pk>/edit/", views.incident_edit, name="edit"),
    path("<int:pk>/notes/", views.add_note, name="add_note"),
    path("<int:pk>/investigate/", views.investigate, name="investigate"),
    path("<int:pk>/escalate/", views.escalate, name="escalate"),
    path("<int:pk>/false-positive/", views.false_positive, name="false_positive"),
    path("<int:pk>/close/", views.close, name="close"),
    path("<int:pk>/reopen/", views.reopen, name="reopen"),
]
