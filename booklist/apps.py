from django.apps import AppConfig


class BooklistConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'booklist'

class UsersConfig(AppConfig):
    name = 'booklist'

    def ready(self):
        import booklist.signals
        