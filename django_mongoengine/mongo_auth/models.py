from django.utils.encoding import smart_str
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.contrib.auth.models import (
    AbstractBaseUser,
    _user_has_perm, _user_get_all_permissions, _user_has_module_perms,
)
from django.db import models
from django.contrib import auth

from bson.objectid import ObjectId
from mongoengine import ImproperlyConfigured, CASCADE, PULL

from django_mongoengine import document
from django_mongoengine import fields
from .managers import MongoUserManager

UNUSABLE_PASSWORD_PREFIX = '!'  # This will never be a valid encoded hash

try:
    from django.contrib.auth.hashers import check_password, make_password, is_password_usable
except ImportError:
    """Handle older versions of Django"""
    from django.utils.hashcompat import md5_constructor, sha_constructor

    def get_hexdigest(algorithm, salt, raw_password):
        raw_password, salt = smart_str(raw_password), smart_str(salt)
        if algorithm == 'md5':
            return md5_constructor(salt + raw_password).hexdigest()
        elif algorithm == 'sha1':
            return sha_constructor(salt + raw_password).hexdigest()
        raise ValueError('Got unknown password algorithm type in password')

    def is_password_usable(encoded):
        if encoded is None or encoded.startswith(UNUSABLE_PASSWORD_PREFIX):
            return False
        # assumes is true - don't need to handle older previous for ericsson's needs yet
        return True

    def check_password(raw_password, password):
        algo, salt, hash = password.split('$')
        return hash == get_hexdigest(algo, salt, raw_password)

    def make_password(raw_password):
        from random import random
        algo = 'sha1'
        salt = get_hexdigest(algo, str(random()), str(random()))[:5]
        hash = get_hexdigest(algo, salt, raw_password)
        return '%s$%s$%s' % (algo, salt, hash)


class BaseUser(object):

    is_anonymous = AbstractBaseUser.__dict__['is_anonymous']
    is_authenticated = AbstractBaseUser.__dict__['is_authenticated']

#from mongoengine.queryset.manager import QuerySetManager
from mongoengine.queryset.base import BaseQuerySet
from django_mongoengine.queryset import QuerySetManager
BaseQuerySet._prefetch_related_lookups = True


class OptionalEmailField(fields.EmailField):

    def validate(self, value):
        if not value:
            return
        super().validate(value)


class ContentTypeManager(QuerySetManager):
    use_in_migrations = True

    def __init__(self, *args, **kwargs):
        super(ContentTypeManager, self).__init__(*args, **kwargs)
        # Cache shared by all the get_for_* methods to speed up
        # ContentType retrieval.
        self._cache = {}

    def get_by_natural_key(self, app_label, model):
        try:
            ct = self._cache[self.db][(app_label, model)]
        except KeyError:
            ct = self.get(app_label=app_label, model=model)
            self._add_to_cache(self.db, ct)
        return ct

    def _get_opts(self, model, for_concrete_model):
        if for_concrete_model:
            model = model._meta.concrete_model
        return model._meta

    def _get_from_cache(self, opts):
        key = (opts.app_label, opts.model_name)
        return self._cache[self.db][key]

    def get_for_model(self, model, for_concrete_model=True):
        """
        Returns the ContentType object for a given model, creating the
        ContentType if necessary. Lookups are cached so that subsequent lookups
        for the same model don't hit the database.
        """
        opts = self._get_opts(model, for_concrete_model)
        try:
            return self._get_from_cache(opts)
        except KeyError:
            pass

        # The ContentType entry was not found in the cache, therefore we
        # proceed to load or create it.
        try:
            # Start with get() and not get_or_create() in order to use
            # the db_for_read (see #20401).
            ct = self.get(app_label=opts.app_label, model=opts.model_name)
        except self.model.DoesNotExist:
            # Not found in the database; we proceed to create it. This time
            # use get_or_create to take care of any race conditions.
            ct, created = self.get_or_create(
                app_label=opts.app_label,
                model=opts.model_name,
            )
        self._add_to_cache(self.db, ct)
        return ct

    def get_for_models(self, *models, **kwargs):
        """
        Given *models, returns a dictionary mapping {model: content_type}.
        """
        for_concrete_models = kwargs.pop('for_concrete_models', True)
        # Final results
        results = {}
        # models that aren't already in the cache
        needed_app_labels = set()
        needed_models = set()
        needed_opts = set()
        for model in models:
            opts = self._get_opts(model, for_concrete_models)
            try:
                ct = self._get_from_cache(opts)
            except KeyError:
                needed_app_labels.add(opts.app_label)
                needed_models.add(opts.model_name)
                needed_opts.add(opts)
            else:
                results[model] = ct
        if needed_opts:
            cts = self.filter(
                app_label__in=needed_app_labels,
                model__in=needed_models
            )
            for ct in cts:
                model = ct.model_class()
                if model._meta in needed_opts:
                    results[model] = ct
                    needed_opts.remove(model._meta)
                self._add_to_cache(self.db, ct)
        for opts in needed_opts:
            # These weren't in the cache, or the DB, create them.
            ct = self.create(
                app_label=opts.app_label,
                model=opts.model_name,
            )
            self._add_to_cache(self.db, ct)
            results[ct.model_class()] = ct
        return results

    def get_for_id(self, id):
        """
        Lookup a ContentType by ID. Uses the same shared cache as get_for_model
        (though ContentTypes are obviously not created on-the-fly by get_by_id).
        """
        try:
            ct = self._cache[self.db][id]
        except KeyError:
            # This could raise a DoesNotExist; that's correct behavior and will
            # make sure that only correct ctypes get stored in the cache dict.
            ct = self.get(pk=id)
            self._add_to_cache(self.db, ct)
        return ct

    def clear_cache(self):
        """
        Clear out the content-type cache. This needs to happen during database
        flushes to prevent caching of "stale" content type IDs (see
        django.contrib.contenttypes.management.update_contenttypes for where
        this gets called).
        """
        self._cache.clear()

    def _add_to_cache(self, using, ct):
        """Insert a ContentType into the cache."""
        # Note it's possible for ContentType objects to be stale; model_class() will return None.
        # Hence, there is no reliance on model._meta.app_label here, just using the model fields instead.
        key = (ct.app_label, ct.model)
        self._cache.setdefault(using, {})[key] = ct
        self._cache.setdefault(using, {})[ct.id] = ct
    _prefetch_related_lookups = False


class ContentType(document.Document):
    name = fields.StringField(max_length=100)
    app_label = fields.StringField(max_length=100)
    model = fields.StringField(max_length=100, verbose_name=_('python model class name'),
                        unique_with='app_label')
    objects = ContentTypeManager()

    class Meta:
        verbose_name = _('content type')
        verbose_name_plural = _('content types')
        # db_table = 'django_content_type'
        # ordering = ('name',)
        # unique_together = (('app_label', 'model'),)

    def __unicode__(self):
        return self.name

    def model_class(self):
        "Returns the Python model class for this type of content."
        from django.db import models
        return models.get_model(self.app_label, self.model)

    def get_object_for_this_type(self, **kwargs):
        """
        Returns an object of this type for the keyword arguments given.
        Basically, this is a proxy around this object_type's get_object() model
        method. The ObjectNotExist exception, if thrown, will not be caught,
        so code that calls this method should catch it.
        """
        return self.model_class()._default_manager.using(self._state.db).get(**kwargs)

    def natural_key(self):
        return (self.app_label, self.model)


class SiteProfileNotAvailable(Exception):
    pass


class PermissionManager(QuerySetManager):
    def get_by_natural_key(self, codename, app_label, model):
        return self.get(
            codename=codename,
            content_type=ContentType.objects.get_by_natural_key(app_label, model)
        )


class Permission(document.Document):
    """The permissions system provides a way to assign permissions to specific
    users and groups of users.

    The permission system is used by the Django admin site, but may also be
    useful in your own code. The Django admin site uses permissions as follows:

        - The "add" permission limits the user's ability to view the "add"
          form and add an object.
        - The "change" permission limits a user's ability to view the change
          list, view the "change" form and change an object.
        - The "delete" permission limits the ability to delete an object.

    Permissions are set globally per type of object, not per specific object
    instance. It is possible to say "Mary may change news stories," but it's
    not currently possible to say "Mary may change news stories, but only the
    ones she created herself" or "Mary may only change news stories that have
    a certain status or publication date."

    Three basic permissions -- add, change and delete -- are automatically
    created for each Django model.
    """
    name = fields.StringField(max_length=50, verbose_name=_('name'))
    content_type = fields.ReferenceField(ContentType, reverse_delete_rule=CASCADE)
    codename = fields.StringField(max_length=100, verbose_name=_('codename'))
        # FIXME: don't access field of the other class
        # unique_with=['content_type__app_label', 'content_type__model'])

    objects = PermissionManager()

    class Meta:
        verbose_name = _('permission')
        verbose_name_plural = _('permissions')
        # unique_together = (('content_type', 'codename'),)
        # ordering = ('content_type__app_label', 'content_type__model', 'codename')

    def __unicode__(self):
        return u"%s | %s | %s" % (
            (self.content_type.app_label),
            (self.content_type),
            (self.name))

    def natural_key(self):
        return (self.codename,) + self.content_type.natural_key()
    natural_key.dependencies = ['contenttypes.contenttype']

    _prefetch_related_lookups = False


fields.ObjectIdField.auto_created = False

class Group(document.Document):
    """Groups are a generic way of categorizing users to apply permissions,
    or some other label, to those users. A user can belong to any number of
    groups.

    A user in a group automatically has all the permissions granted to that
    group. For example, if the group Site editors has the permission
    can_edit_home_page, any user in that group will have that permission.

    Beyond permissions, groups are a convenient way to categorize users to
    apply some label, or extended functionality, to them. For example, you
    could create a group 'Special users', and you could write code that would
    do special things to those users -- such as giving them access to a
    members-only portion of your site, or sending them members-only
    e-mail messages.
    """
    name = fields.StringField(max_length=80, unique=True, verbose_name=_('name'))
    permissions = fields.ListField(fields.ReferenceField(Permission, reverse_delete_rule=PULL),
            verbose_name=_('permissions'), blank=True, required=False)

    class Meta:
        verbose_name = _('group')
        verbose_name_plural = _('groups')

    def __unicode__(self):
        return self.name


class AbstractUser(BaseUser, document.Document):
    """A User document that aims to mirror most of the API specified by Django
    at http://docs.djangoproject.com/en/dev/topics/auth/#users
    """
    username = fields.StringField(
        max_length=30, verbose_name=_('username'),
        help_text=_("Required. 30 characters or fewer. Letters, numbers and @/./+/-/_ characters"),
    )

    first_name = fields.StringField(
        max_length=30, blank=True, verbose_name=_('first name'),
    )

    last_name = fields.StringField(
        max_length=30, blank=True, verbose_name=_('last name'))
    email = OptionalEmailField(verbose_name=_('e-mail address'), blank=True, required=False)
    password = fields.StringField(
        # need to set default - to allow django to proceed in two steps
        # to create user with unusable password
        default='',
        max_length=128,
        verbose_name=_('password'),
        help_text=_("Use '[algo]$[iterations]$[salt]$[hexdigest]' or use the <a href=\"password/\">change password form</a>."))
    is_staff = fields.BooleanField(
        default=False,
        blank=True,
        verbose_name=_('staff status'),
        help_text=_("Designates whether the user can log into this admin site."))
    is_active = fields.BooleanField(
        default=True,
        verbose_name=_('active'),
        help_text=_("Designates whether this user should be treated as active. Unselect this instead of deleting accounts."))
    is_superuser = fields.BooleanField(
        default=False,
        blank=True,
        verbose_name=_('superuser status'),
        help_text=_("Designates that this user has all permissions without explicitly assigning them."))
    last_login = fields.DateTimeField(
        default=timezone.now,
        verbose_name=_('last login'))
    date_joined = fields.DateTimeField(
        default=timezone.now,
        verbose_name=_('date joined'))

    user_permissions = fields.ListField(
        fields.ReferenceField(Permission, reverse_delete_rule=PULL), verbose_name=_('user permissions'),
        blank=True, help_text=_('Permissions for the user.'))

    groups = fields.ListField(
        fields.ReferenceField(Group, reverse_delete_rule=PULL), verbose_name=_('user groups'),
        blank=True, help_text=_('Groups for the user.'))

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    meta = {
        'abstract': True,
        'indexes': [
            {'fields': ['username'], 'unique': True, 'sparse': True}
        ]
    }

    def __unicode__(self):
        return self.username

    def get_username(self):
        return self.username

    def get_full_name(self):
        """Returns the users first and last names, separated by a space.
        """
        full_name = u'%s %s' % (self.first_name or '', self.last_name or '')
        return full_name.strip()

    def set_password(self, raw_password):
        """Sets the user's password - always use this rather than directly
        assigning to :attr:`~mongoengine.django.auth.User.password` as the
        password is hashed before storage.
        """
        self.password = make_password(raw_password)
        self.save()
        return self

    def check_password(self, raw_password):
        """Checks the user's password against a provided password - always use
        this rather than directly comparing to
        :attr:`~mongoengine.django.auth.User.password` as the password is
        hashed before storage.
        """
        return check_password(raw_password, self.password)

    def set_unusable_password(self):
        """Sets an unusable password,
        starting with proper django's unusable prefix "!" & random hash"""
        self.password = make_password(None)
        self.save()
        return self

    def has_usable_password(self):
        return is_password_usable(self.password)

    @classmethod
    def create_user(cls, username, password, email=None, **kwargs):
        """Create (and save) a new user with the given username, password and
        email address.
        """
        now = timezone.now()

        # Normalize the address by lowercasing the domain part of the email
        # address.
        if email is not None:
            try:
                email_name, domain_part = email.strip().split('@', 1)
            except ValueError:
                pass
            else:
                email = '@'.join([email_name, domain_part.lower()])

        user = cls(username=username, email=email, date_joined=now, **kwargs)
        user.set_password(password)
        user.save()
        return user

    def get_group_permissions(self, obj=None):
        """
        Returns a list of permission strings that this user has through his/her
        groups. This method queries all available auth backends. If an object
        is passed in, only permissions matching this object are returned.
        """
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_group_permissions"):
                permissions.update(backend.get_group_permissions(self, obj))
        return permissions

    def get_all_permissions(self, obj=None):
        return _user_get_all_permissions(self, obj)

    def has_perm(self, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general. If an object is
        provided, permissions for this specific object are checked.
        """

        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions. If
        object is passed, it checks if the user has all required perms for this
        object.
        """
        return all(self.has_perm(perm, obj) for perm in perm_list)

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permissions in the given app label.
        Uses pretty much the same logic as has_perm, above.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        return _user_has_module_perms(self, app_label)

    def email_user(self, subject, message, from_email=None):
        "Sends an e-mail to this User."
        from django.core.mail import send_mail
        send_mail(subject, message, from_email, [self.email])

    def get_profile(self):
        """
        Returns site-specific profile for this user. Raises
        SiteProfileNotAvailable if this site does not allow profiles.
        """
        if not hasattr(self, '_profile_cache'):
            from django.conf import settings
            if not getattr(settings, 'AUTH_PROFILE_MODULE', False):
                raise SiteProfileNotAvailable('You need to set AUTH_PROFILE_MO'
                                              'DULE in your project settings')
            try:
                app_label, model_name = settings.AUTH_PROFILE_MODULE.split('.')
            except ValueError:
                raise SiteProfileNotAvailable('app_label and model_name should'
                        ' be separated by a dot in the AUTH_PROFILE_MODULE set'
                        'ting')

            try:
                model = models.get_model(app_label, model_name)
                if model is None:
                    raise SiteProfileNotAvailable('Unable to load the profile '
                        'model, check AUTH_PROFILE_MODULE in your project sett'
                        'ings')
                self._profile_cache = model._default_manager.using(self._state.db).get(user__id__exact=self.id)
                self._profile_cache.user = self
            except (ImportError, ImproperlyConfigured):
                raise SiteProfileNotAvailable
        return self._profile_cache


    @classmethod
    def normalize_username(cls, username):
        return username

class User(AbstractUser):
    meta = {'allow_inheritance': True}

class MongoUser(BaseUser, models.Model):
    """"
    Dummy user model for Django.

    MongoUser is used to replace Django's UserManager with MongoUserManager.
    The actual user document class is django_mongoengine.auth.models.User or any
    other document class specified in MONGOENGINE_USER_DOCUMENT.

    To get the user document class, use `get_user_document()`.

    """

    objects = MongoUserManager()

    class Meta:
        app_label = 'mongo_auth'

    def set_password(self, password):
        """Doesn't do anything, but works around the issue with Django 1.6."""
        make_password(password)

    @classmethod
    def normalize_username(cls, username):
        return username
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )
    email = models.EmailField(verbose_name=_('e-mail address'), blank=True)


MongoUser._meta.pk.to_python = ObjectId

for model in (User, Group, Permission, ContentType):
    for field in model._fields.values():
        field.auto_created = False


