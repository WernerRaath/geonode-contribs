# -*- coding: utf-8 -*-
#########################################################################
#
# Copyright (C) 2016 OSGeo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################

from django import template
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.db.models import Count

from guardian.shortcuts import get_objects_for_user
from geonode import settings
from geonode.base.models import HierarchicalKeyword

from geonode.layers.models import Layer
from geonode.maps.models import Map
from geonode.documents.models import Document
from geonode.groups.models import GroupProfile

from geonode.contrib.geosites.utils import resources_for_site, users_for_site
from geonode.security.utils import get_visible_resources

register = template.Library()


@register.simple_tag(takes_context=True)
def site_facets(context):
    request = context['request']
    title_filter = request.GET.get('title__icontains', '')
    extent_filter = request.GET.get('extent', None)
    keywords_filter = request.GET.getlist('keywords__slug__in', None)
    category_filter = request.GET.getlist('category__identifier__in', None)
    regions_filter = request.GET.getlist('regions__name__in', None)
    owner_filter = request.GET.getlist('owner__username__in', None)
    date_gte_filter = request.GET.get('date__gte', None)
    date_lte_filter = request.GET.get('date__lte', None)
    date_range_filter = request.GET.get('date__range', None)

    facet_type = context['facet_type'] if 'facet_type' in context else 'all'

    if not settings.SKIP_PERMS_FILTER:
        authorized = get_objects_for_user(
            request.user, 'base.view_resourcebase').values('id')

    if facet_type == 'documents':

        documents = Document.objects.filter(title__icontains=title_filter).filter(id__in=resources_for_site())

        if category_filter:
            documents = documents.filter(category__identifier__in=category_filter)

        if regions_filter:
            documents = documents.filter(regions__name__in=regions_filter)

        if owner_filter:
            documents = documents.filter(owner__username__in=owner_filter)

        if date_gte_filter:
            documents = documents.filter(date__gte=date_gte_filter)
        if date_lte_filter:
            documents = documents.filter(date__lte=date_lte_filter)
        if date_range_filter:
            documents = documents.filter(date__range=date_range_filter.split(','))

        documents = get_visible_resources(
            documents,
            request.user if request else None,
            request=request,
            admin_approval_required=settings.ADMIN_MODERATE_UPLOADS,
            unpublished_not_visible=settings.RESOURCE_PUBLISHING,
            private_groups_not_visibile=settings.GROUP_PRIVATE_RESOURCES)

        if keywords_filter:
            treeqs = HierarchicalKeyword.objects.none()
            for keyword in keywords_filter:
                try:
                    kws = HierarchicalKeyword.objects.filter(name__iexact=keyword)
                    for kw in kws:
                        treeqs = treeqs | HierarchicalKeyword.get_tree(kw)
                except Exception:
                    # Ignore keywords not actually used?
                    pass

            documents = documents.filter(Q(keywords__in=treeqs))

        if not settings.SKIP_PERMS_FILTER:
            documents = documents.filter(id__in=authorized)

        counts = documents.values('doc_type').annotate(count=Count('doc_type'))
        facets = dict([(count['doc_type'], count['count']) for count in counts])

        return facets

    else:

        layers = Layer.objects.filter(title__icontains=title_filter).filter(id__in=resources_for_site())

        if category_filter:
            layers = layers.filter(category__identifier__in=category_filter)

        if regions_filter:
            layers = layers.filter(regions__name__in=regions_filter)

        if owner_filter:
            layers = layers.filter(owner__username__in=owner_filter)

        if date_gte_filter:
            layers = layers.filter(date__gte=date_gte_filter)
        if date_lte_filter:
            layers = layers.filter(date__lte=date_lte_filter)
        if date_range_filter:
            layers = layers.filter(date__range=date_range_filter.split(','))

        layers = get_visible_resources(
            layers,
            request.user if request else None,
            request=request,
            admin_approval_required=settings.ADMIN_MODERATE_UPLOADS,
            unpublished_not_visible=settings.RESOURCE_PUBLISHING,
            private_groups_not_visibile=settings.GROUP_PRIVATE_RESOURCES)

        if extent_filter:
            bbox = extent_filter.split(
                ',')  # TODO: Why is this different when done through haystack?
            bbox = map(str, bbox)  # 2.6 compat - float to decimal conversion
            intersects = ~(Q(bbox_x0__gt=bbox[2]) | Q(bbox_x1__lt=bbox[0]) |
                           Q(bbox_y0__gt=bbox[3]) | Q(bbox_y1__lt=bbox[1]))

            layers = layers.filter(intersects)

        if keywords_filter:
            treeqs = HierarchicalKeyword.objects.none()
            for keyword in keywords_filter:
                try:
                    kws = HierarchicalKeyword.objects.filter(name__iexact=keyword)
                    for kw in kws:
                        treeqs = treeqs | HierarchicalKeyword.get_tree(kw)
                except Exception:
                    # Ignore keywords not actually used?
                    pass

            layers = layers.filter(Q(keywords__in=treeqs))

        if not settings.SKIP_PERMS_FILTER:
            layers = layers.filter(id__in=authorized)

        counts = layers.values('storeType').annotate(count=Count('storeType'))
        count_dict = dict([(count['storeType'], count['count']) for count in counts])

        vector_time_series = layers.exclude(has_time=False).filter(storeType='dataStore'). \
            values('storeType').annotate(count=Count('storeType'))

        if vector_time_series:
            count_dict['vectorTimeSeries'] = vector_time_series[0]['count']

        facets = {
            'raster': count_dict.get('coverageStore', 0),
            'vector': count_dict.get('dataStore', 0),
            'vector_time': count_dict.get('vectorTimeSeries', 0),
            'remote': count_dict.get('remoteStore', 0),
            'wms': count_dict.get('wmsStore', 0),
        }

        # Break early if only_layers is set.
        if facet_type == 'layers':
            return facets

        maps = Map.objects.filter(title__icontains=title_filter).filter(id__in=resources_for_site())
        documents = Document.objects.filter(title__icontains=title_filter).filter(id__in=resources_for_site())

        if category_filter:
            maps = maps.filter(category__identifier__in=category_filter)
            documents = documents.filter(category__identifier__in=category_filter)

        if regions_filter:
            maps = maps.filter(regions__name__in=regions_filter)
            documents = documents.filter(regions__name__in=regions_filter)

        if owner_filter:
            maps = maps.filter(owner__username__in=owner_filter)
            documents = documents.filter(owner__username__in=owner_filter)

        if date_gte_filter:
            maps = maps.filter(date__gte=date_gte_filter)
            documents = documents.filter(date__gte=date_gte_filter)
        if date_lte_filter:
            maps = maps.filter(date__lte=date_lte_filter)
            documents = documents.filter(date__lte=date_lte_filter)
        if date_range_filter:
            maps = maps.filter(date__range=date_range_filter.split(','))
            documents = documents.filter(date__range=date_range_filter.split(','))

        maps = get_visible_resources(
            maps,
            request.user if request else None,
            request=request,
            admin_approval_required=settings.ADMIN_MODERATE_UPLOADS,
            unpublished_not_visible=settings.RESOURCE_PUBLISHING,
            private_groups_not_visibile=settings.GROUP_PRIVATE_RESOURCES)
        documents = get_visible_resources(
            documents,
            request.user if request else None,
            request=request,
            admin_approval_required=settings.ADMIN_MODERATE_UPLOADS,
            unpublished_not_visible=settings.RESOURCE_PUBLISHING,
            private_groups_not_visibile=settings.GROUP_PRIVATE_RESOURCES)

        if extent_filter:
            bbox = extent_filter.split(
                ',')  # TODO: Why is this different when done through haystack?
            bbox = map(str, bbox)  # 2.6 compat - float to decimal conversion
            intersects = ~(Q(bbox_x0__gt=bbox[2]) | Q(bbox_x1__lt=bbox[0]) |
                           Q(bbox_y0__gt=bbox[3]) | Q(bbox_y1__lt=bbox[1]))

            maps = maps.filter(intersects)
            documents = documents.filter(intersects)

        if keywords_filter:
            treeqs = HierarchicalKeyword.objects.none()
            for keyword in keywords_filter:
                try:
                    kws = HierarchicalKeyword.objects.filter(name__iexact=keyword)
                    for kw in kws:
                        treeqs = treeqs | HierarchicalKeyword.get_tree(kw)
                except Exception:
                    # Ignore keywords not actually used?
                    pass

            maps = maps.filter(Q(keywords__in=treeqs))
            documents = documents.filter(Q(keywords__in=treeqs))

        if not settings.SKIP_PERMS_FILTER:
            maps = maps.filter(id__in=authorized)
            documents = documents.filter(id__in=authorized)

        facets['map'] = maps.count()
        facets['document'] = documents.count()

        if facet_type == 'home':
            facets['user'] = get_user_model().objects.exclude(
                username='AnonymousUser').filter(id__in=users_for_site()).count()

            facets['group'] = GroupProfile.objects.exclude(
                access="private").count()

            facets['layer'] = facets['raster'] + \
                facets['vector'] + facets['remote'] + facets['wms']  # + facets['vector_time']

    return facets
