import datetime

from tastypie.authorization import Authorization

def timediff(d):
    return lambda: datetime.datetime.now() + datetime.timedelta(d)

def isnot_super(user):
    return user.is_super == False

def raise_this(exc):
    """
    Needed to lambda:raise
    Python syntax doesn't agree
    """
    raise exc

class RelationalAuthorization(Authorization):
    """
    Relational authorizations mixin.

    Subclass must define a ruleset in the member variable rules.
    Rules mostly follow the Django ORM lookup structure of
    seperating entities with double underscores.  Introspection is
    used to get a comparator from the last lookup, if there is no
    member on the class with the same name.  If no comparator is given,
    equality is assumed.

    The form for a rule is twofold:

    1. Naked rule:

       lhs, rhs = (
           'attribute1__subattribute__comparator_or_attribute',
           'rootitem__attribute'
                  )
       lhs is a lookup on the bundled item or queryset.  rhs is a primitive
       against which the relationship given will be tested for CRUD privileges,
       if the relationship holds.        

    2. Sentinel rule:

       sentinel, (lhs, rhs) = [
                          user_evaluator,
                          ('attribute1__subattribute__comparator_or_attribute',
                           'rootitem__attribute')
                              ]

       sentinel is a function that takes a user as a parameter and returns True 
       if the rule is applied to that users authorizations or False if it
       should not be used.  The rule itself is applied exactly as if it were
       naked.

    Primitives are root objects that provide items to compare data against.
    Some very basic primitives are provided:

        now: datetime.datetime.now()
        yesterday: now - datetime.timedelta(1)
        tomorrow: now + datetime.timedelta(1)
        last_week: now - datetime.timedelta(7)
        next_week: now + datetime.timedelta(7)
        user: alias of request.user
        request: the request initiating the action

    Passing a dict of keys and parameterless lambdas to the constructor will add
    those to available primitives.  Primitives should not need parameters for
    construction.

        class MyAuthorization(GrondalAuthorization):

            def __init__(self, *args, **kwargs):
                kwargs['primitives'] = {
                    'superstring':lambda:u"adminuser",
                    }
                super(MyAuthorization, self).__init__(*args, **kwargs)
    """

    PRIMITIVES = {
        'now': datetime.datetime.now,
        'yesterday': timediff(-1),
        'tomorrow': timediff(1),
        'last_week': timediff(-7),
        'next_week': timediff(+7),
        }

    TRANSLATE_LOOKUPS = {
        'gte':'ge',
        'lte':'le'
        }

    def __init__(self, primitives={}):
        """
        Would be nice to be able to do this
        inline with the basic primitives declaration
        but the class declaration needs variables
        to be declared allready while init
        is not as picky
        """
        self.PRIMITIVES['user'] = lambda:self.user
        self.PRIMITIVES['request'] = lambda:self.request
        self.PRIMITIVES.update(primitives)

    def get_user(self, request):
        from apps.grondal.models.user import User
        """
        This is implementation specific for Grondal,
        needs to be replaced with a more generic component
        """
        token = request.META.get('HTTP_AUTHORIZATION', None)
        pk =  2#grondal_redis.hget(token, 'pk')
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            if settings.DEBUG:
                # return eythor, a super user
                return User.objects.get(pk=2)
            return False

    def introspect(self, item, lookups):
        """
        Perform lookups on variables.
        callable is a bit suspect.
        Should something like __callable(variable)__ be supported?
        Should dict lookups also be supported? Listlookups like in djangotemplates?
        This is a bit of a rabbit hole.
        """
        for lookup in lookups:
            child = getattr(item, lookup, LookupError(lookup + " not on "+ str(item)))
            if type(child) == LookupError:
                raise LookupError
            if callable(child):
                item = child()
            else:
                item = child
        return item

    def normalize_lookups(self, rules, bundle):
        """
        Resolve rhs of lookups to concrete objects that
        can take part in the comparison.
        """
        self.user = self.get_user(bundle.request)
        self.request = bundle.request
        lookups = {}
        lookups_out = {}
        for rule in rules:
            if type(rule) == list:
                sentinel, (lhs, rhs) = rule
                if sentinel(self.user):
                    lookups[lhs] = rhs
            else:
                lhs, rhs = rule
                lookups[lhs] = rhs
        for k, v in lookups.items():
            # This is a bit of a hack, primitives are (or should never be) None
            # Needs to be evaluated sometimes (for current-context variables like time)
            root_item = self.PRIMITIVES.get(v.split("__")[0])()
            lookups_out[k] = self.introspect(root_item, v.split("__")[1:])
        return lookups_out

    def lhslookup(self, obj, lhs, rhs):
        """
        Resolve lhs of lookups to concrete actions
        to compare against a rhs of a rule.
        No entirely happy with the error raised, need
        to find more idiomatic expression of the error.
        """
        lookups = lhs.split("__")
        for lookup in lookups[:-1]:
            lhs = getattr(lhs, lookup)
        lastleg = getattr(lhs, lookups[-1], None)
        if lastleg:
            return lastleg == rhs
        if lookups[-1] in ["in"]: #potentially more fidgets
            return lhs in rhs
        return getattr(
            lhs,
            "__"+self.TRANSLATE_LOOKUPS.get(lookups[-1],lookups[-1])+"__",
            lambda u: raise_this(LookupError(lookups[-1]+" not on "+str(type(lhs))))
            )(rhs)

    def read_list(self, object_list, bundle):
        rules = self.normalize_lookups(self.rules.get('retrieve', {}), bundle)        
        return object_list.filter(**rules)

    def read_detail(self, object_list, bundle):
        return bundle.obj in self.read_list(object_list, bundle)

    def validate_detail(self, detail_object, bundle, auth_method):
        for lhs, rhs in self.normalize_lookups(self.rules.get(auth_method,{}), bundle):
            if not self.lhslookup(detail_object, lhs, rhs):
                return False
        return True

    def create_detail(self, object_list, bundle):
        return self.validate_detail(bundle.obj, bundle, 'create')

    def update_detail(self, object_list, bundle):
        return self.validate_detail(bundle.obj, bundle, 'update')

    def delete_detail(self, object_list, bundle):
        return self.validate_detail(bundle.obj, bundle, 'delete')

    def process_list(self, object_list, bundle, auth_method):
        allowed = []
        for obj in object_list:
            if self.validate_detail(obj, bundle, auth_method):
                allowed.append(obj)
        return allowed

    def update_list(self, object_list, bundle):
        return self.process_list(object_list, bundle, 'update')

    def delete_list(self, object_list, bundle):
        return self.process_list(object_list, bundle, 'delete')

    def create_list(self, object_list, bundle):
        return self.process_list(object_list, bundle, 'create')
        

