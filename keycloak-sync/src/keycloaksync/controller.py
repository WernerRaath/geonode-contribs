import os
if __name__ == '__main__':
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
    import django
    django.setup()
    from django.core.management import execute_from_command_line

    execute_from_command_line(['manage.py', 'migrate'])

import json, logging, re
import datetime as dt
import requests

from django.db.models import Q
from django.conf import settings
from django.core import serializers

from geonode.groups.models import GroupProfile, GroupCategory, GroupMember
from django.contrib.auth.models import Group

from geonode.people.models import Profile
from allauth.socialaccount.models import SocialAccount

from oauth2_provider.models import AccessToken, Application

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s', datefmt='%d-%b-%y %H:%M:%S') 
logger = logging.getLogger(__name__)


def get_token():
    url = f'{settings.KEYCLOAK_URL}/realms/master/protocol/openid-connect/token'
    if settings.KEYCLOAK_USER:
        rqdata = {
            'username': settings.KEYCLOAK_USER,
            'password': settings.KEYCLOAK_PASSWORD,
            'grant_type': 'password',
            'client_id': 'admin-cli'
        }
    else:
        rqdata = {
            'client_id': settings.KEYCLOAK_CLIENT,
            'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            'grant_type': settings.KEYCLOAK_GRANT_TYPE,
            'scope': settings.KEYCLOAK_SCOPE,
        }
    resp = requests.post(url=url, data=rqdata)
    data = resp.json()
    access_token = data.get('access_token', None)
    if not access_token:
        r = f'{resp.status_code}: {resp.text} for data {rqdata}'
        raise Exception(f'Access token not found in response: {r}')
    return access_token

def get_json(url):
    token = get_token()
    headers = {
        'Authorization': f'Bearer {token}',
    }
    resp = requests.get(url=url, headers=headers)
    return resp.json()

def get_users(max=5000):
    url = f'{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users?max={max}&briefRepresentation=false'
    users = get_json(url)
    return users

def get_user(id):
    url = f'{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{id}'
    user = get_json(url)
    return user

def get_groups(max=5000):
    url = f'{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/groups?max={max}&briefRepresentation=false'
    groups = get_json(url)
    return groups

def get_group_members(group_id, max=5000):
    url = f'{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/groups/{group_id}/members?max={max}&briefRepresentation=false'
    groups = get_json(url)
    return groups

def get_roles():
    url = f'{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/clients/{settings.KEYCLOAK_CLIENT}/roles'
    roles = get_json(url)
    return roles

def flatten_groups(groups, parent_id=None):
    flattened = []
    for g in groups:
        sg = g['subGroups']
        g['parentGroup'] = parent_id
        g.pop('subGroups')
        flattened.append(g)
        if len(sg):
            flattened += flatten_groups(sg, g['id'])
    return flattened

def group_identifier(group):
    name = re.sub('[^a-zA-Z0-9 \n\.]', '-', group['name']).replace(' ', '-')
    name = re.sub(r'(-)+', r'\1', name)
    tag = f"keycloak_{group['id']}_{name}"
    return tag

def group_identifier_extract_id(identifier):
    return identifier.split('_')[1]

def username_wrapper(username):
    if username == 'admin':
        username = 'keycloak_admin'
    return username

def sync_users(group_slugs = []):
    summary = {}
    kc_group_members = []
    for group_slug in group_slugs:
        group_members = get_group_members(group_identifier_extract_id(group_slug))
        kc_group_members += [{'group': group_slug, 'user': gm['id']} for gm in group_members]
    
    kc_users = get_users()
    kc_accounts = [kcu for kcu in kc_users if kcu['enabled']]
    social_account_ids = [kcu['id'] for kcu in kc_accounts]
    
    SocialAccounts = SocialAccount.objects.filter(provider='keycloak')
    existing_social_accounts = SocialAccounts.filter(uid__in=social_account_ids)
    existing_social_account_ids = [sa.uid for sa in existing_social_accounts]

    updated_profiles = []
    new_profiles = []
    new_social_accounts = []
    updated_social_accounts = []
    for kcu in kc_accounts:
        uid = kcu['id']
        username = username_wrapper(kcu['username'])
        email = kcu.get('email', '')
        firstName = kcu.get('firstName', '')
        lastName = kcu.get('lastName', '')

        profile = Profile.objects.filter(username=username).first()
        if profile:
            profile.email = email
            profile.first_name = firstName
            profile.last_name = lastName
            updated_profiles.append(profile)
        if uid not in existing_social_account_ids and not profile:
            profile = Profile(
                username=username,
                email=email,
                first_name=firstName,
                last_name=lastName
            )
            new_profiles.append(profile)
    
    delete_social_accounts = SocialAccounts.filter(~Q(uid__in=social_account_ids))
    deleted_social_accounts = list(delete_social_accounts)
    delete_profiles = Profile.objects.filter(username__in=[sa.user.username for sa in delete_social_accounts])
    deleted_profiles = list(delete_profiles)
  
    logging.info(f'Keycloak User Profile Bulk Delete initiated')
    delete_profiles.delete()

    logging.info(f'Keycloak User Profile Bulk Create initiated')
    Profile.objects.bulk_create(new_profiles)
    new_profiles = Profile.objects.filter(username__in=[p.username for p in new_profiles])
    if not len(group_slugs):
        logging.info(f'Keycloak User Profile Group Assign SKIPPED')
    else:
        logging.info(f'Keycloak User Profile Group Assign initiated')
        new_group_members = []
        delete_group_members = []
        for kcu in kc_accounts:
            username = username_wrapper(kcu['username'])
            profile = Profile.objects.filter(username=username).first()
            if profile:
                group_names = [kc['group'] for kc in kc_group_members if kc['user'] == kcu['id']]
                groups = Group.objects.filter(name__in=group_names)
                profile.groups.set(groups)

                profile_group_members = GroupMember.objects.filter(user=profile)
                delete_group_members.append(profile_group_members.filter(~Q(group__slug__in=group_names)))
                
                group_profiles = GroupProfile.objects.filter(slug__in=group_names)
                for gp in group_profiles:
                    gm = GroupMember.objects.filter(user=profile, group=gp).first()
                    if not gm:
                        gm = GroupMember(user=profile, group=gp, role='member')
                        new_group_members.append(gm)
            else:
                logger.warning(f'Group Allocation: Profile does not exists for ID: {kcu["id"]}')
        
        logging.info(f'Keycloak Group Member Bulk Create initiated')
        GroupMember.objects.bulk_create(new_group_members)
        logging.info(f'Keycloak Group Member Bulk Delete initiated')
        deleted_group_members = []
        for dgm in delete_group_members:
            deleted_group_members += list(dgm)
            dgm.delete()
        
        summary["group_members"] = {
            "new": new_group_members,
            "deleted": deleted_group_members
        }
    
    for kcu in kc_accounts:
        uid = kcu['id']
        username = username_wrapper(kcu['username'])
        extra_data = {
            "email_verified": kcu.get('emailVerified', False),
            "name": kcu.get('firstName', ''),
            "groups": kcu.get('groups', []),
            "preferred_username": username,
            "given_name": f"{kcu.get('firstName', '')} {kcu.get('lastName', '')}",
            "email": kcu.get('email', ''),
            "id": kcu.get('id', '')
        }
        if uid not in existing_social_account_ids:
            profile = Profile.objects.filter(username=username).first()
            social_account = SocialAccount(
                uid=uid,
                provider='keycloak',
                user=profile,
                extra_data=extra_data
            )
            new_social_accounts.append(social_account)
        else:
            social_account = existing_social_accounts.filter(uid=uid).first()
            social_account.extra_data = extra_data
            updated_social_accounts.append(social_account)

    logging.info(f'Keycloak User SocialAccount Bulk Create initiated')
    SocialAccount.objects.bulk_create(new_social_accounts)
    new_social_accounts = SocialAccount.objects.filter(uid__in=[sa.uid for sa in new_social_accounts])
    logging.info(f'Keycloak User SocialAccount Bulk Update initiated')
    SocialAccount.objects.bulk_update(updated_social_accounts, ['extra_data'])

    logging.info(f'Keycloak User Profile Bulk Update initiated')
    Profile.objects.bulk_update(updated_profiles, ['email', 'first_name', 'last_name'])

    geoserver_application = Application.objects.filter(name='GeoServer').first()
    if geoserver_application is None:
        application_options = [app.name for app in Application.objects.all()]
        raise Exception(f'No Django OAuth Toolkit Application named "GeoServer". Options are: {application_options}')
    
    if settings.USE_ID_AS_SOCIAL_TOKEN:
        new_access_tokens = []
        updated_access_tokens = []
        for sa in list(new_social_accounts) + updated_social_accounts:
            at = AccessToken.objects.filter(application=geoserver_application, user=sa.user).first()
            isNew = at is None
            if isNew:
                at = AccessToken(application=geoserver_application, user=sa.user, token=sa.uid)
            at.expires = dt.datetime.now() + dt.timedelta(days=366)
            if isNew:
                new_access_tokens.append(at)
            else:
                updated_access_tokens.append(at)
        
        delete_access_tokens = AccessToken.objects.filter(application=geoserver_application).filter(~Q(token__in=[kcu['id'] for kcu in kc_accounts]))
        deleted_access_tokens = list(delete_access_tokens)

        logging.info(f'Keycloak User AccessToken Bulk Delete initiated')
        delete_access_tokens.delete()

        logging.info(f'Keycloak User AccessToken Bulk Create initiated')
        AccessToken.objects.bulk_create(new_access_tokens)
        logging.info(f'Keycloak User Profile Bulk Update initiated')
        AccessToken.objects.bulk_update(updated_access_tokens, ['expires'])
        summary["access_tokens"] = {
            "new": new_access_tokens,
            "updated": updated_access_tokens,
            "deleted": deleted_access_tokens
        }

    logging.info(f'Keycloak User sync summary: {len(new_profiles)} New, {len(existing_social_account_ids)} Updated, {len(deleted_social_accounts)} Deleted, {len(SocialAccount.objects.filter(provider="keycloak"))} Total')

    summary["profiles"] = {
        "new": new_profiles,
        "updated": updated_profiles,
        "deleted": deleted_profiles
    }
    summary["social_accounts"] = {
        "new": new_social_accounts,
        "updated": updated_social_accounts,
        "deleted": deleted_social_accounts
    }

    return summary

# sync_groups fetches groups from KeyCloak,
# flattens their tree structure,
# and creates groups that are not in the database,
# updates those that are
# and deletes those that are not in KeyCloak anymore
def sync_groups():
    kc_groups = get_groups()
    kc_groups = flatten_groups(kc_groups)

    group_ids = [group_identifier(kcu) for kcu in kc_groups]

    GroupProfiles = GroupProfile.objects.filter(slug__startswith='keycloak_')
    Groups = Group.objects.filter(name__startswith='keycloak_')
    
    existing_group_profiles = GroupProfiles.filter(slug__in=group_ids)
    existing_group_profile_ids = [sa.slug for sa in existing_group_profiles]

    new_groups = []
    new_group_profiles = []

    for kcu in kc_groups:
        uid = group_identifier(kcu)
        group = Groups.filter(name=uid).first()
        if not group:
            group = Group(
                name=uid
            )
            new_groups.append(group)
    
    delete_group_profiles = GroupProfiles.filter(~Q(slug__in=group_ids))
    delete_groups = Groups.filter(~Q(name__in=group_ids))

    logging.info(f'Keycloak Group Bulk Delete initiated')
    deleted_groups = list(delete_groups)
    delete_groups.delete()
  
    logging.info(f'Keycloak Group Bulk Create initiated')
    Group.objects.bulk_create(new_groups)
    new_groups = Group.objects.filter(name__in=[g.name for g in new_groups])

    for kcu in kc_groups:
        group_id = group_identifier(kcu)
        title = kcu.get('path', None)
        name = kcu.get('name', None)
        if group_id not in existing_group_profile_ids:
            group = Groups.filter(name=group_id).first()
            social_account = GroupProfile(
                title=name,
                slug=group_id,
                description=title,
                group=group,
                access='private'
            )
            new_group_profiles.append(social_account)

    logging.info(f'Keycloak GroupProfile Bulk Delete initiated')
    deleted_group_profiles = list(delete_group_profiles)
    delete_group_profiles.delete()

    logging.info(f'Keycloak GroupProfile Bulk Create initiated')
    GroupProfile.objects.bulk_create(new_group_profiles)
    new_group_profiles = GroupProfile.objects.filter(slug__in=[gp.slug for gp in new_group_profiles])
    
    keycloak_group_category, _ = GroupCategory.objects.get_or_create(name='keycloak', description='GroupProfile created by "keycloaksync" module')
    for ngp in new_group_profiles:
        ngp.categories.add(keycloak_group_category)

    logging.info(f'Keycloak Group sync summary: {len(new_group_profiles)} New, {len(existing_group_profiles)} Updated, {len(deleted_group_profiles)} Deleted, {len(GroupProfile.objects.filter(description__startswith="keycloak_"))} Total')
    return {
        "group_profiles": {
            "new": new_group_profiles,
            "updated": existing_group_profiles,
            "deleted": deleted_group_profiles
        },
        "groups": {
            "new": new_groups,
            "deleted": deleted_groups
        }
    }

def sync_all():
    group_summary = sync_groups()
    group_slugs = []
    for crud_key in group_summary['group_profiles']:
        group_slugs += [gs.slug for gs in group_summary['group_profiles'][crud_key] ]
    user_summary = sync_users(group_slugs)

    full_summary = {**group_summary, **user_summary}

    
    return full_summary

def summary_to_json(summary):
    simplified = {}
    for model_key in summary:
        simplified[model_key] = {}
        for crud_key in summary[model_key]:
            data_list = summary[model_key][crud_key]
            simplified[model_key][crud_key] = json.loads(serializers.serialize("json", data_list))
    return simplified

if __name__ == '__main__':
    summary = sync_all()
    summary_json = summary_to_json(summary)
    # logger.info(summary_json)