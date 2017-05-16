"""
Copyright (c) Ericsson Television AB
All rights reserved.
No part of this program may be reproduced, translated or transmitted,
in any form or by any means, electronic, mechanical, photocopying,
recording or otherwise, or stored in any retrieval system of any nature,
without the written permission of the copyright holder.
"""

from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _


class MongoAuthConfig(AppConfig):

    name = "django_mongoengine.mongo_auth"
    # verbose_name = _("mongo_auth")
    verbose_name = _("User Management")