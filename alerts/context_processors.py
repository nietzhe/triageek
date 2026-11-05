from .models import Alert

def sample_data(request):
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {}
    return {"has_demo_data": Alert.objects.filter(is_demo=True).exists()}
