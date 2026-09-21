"""Named, replayable user journeys for the screenshot catalog."""
from copy import deepcopy
ID = '123e4567-e89b-42d3-a456-426614174000'
MID = '223e4567-e89b-42d3-a456-426614174000'
DID = '323e4567-e89b-42d3-a456-426614174000'
CODE = 'sirin1.' + 'SCREENSHOT-EXAMPLE-' * 80
KEY = 'sirk1.' + 'RECOVERY-EXAMPLE-' * 45
ERROR = 'The VPS could not be reached. Check the connection and try again.'

def click(text, exact=True, **kw):
    return {'text': text, 'exact': exact, **kw}

def fill(label, value):
    return {'label': label, 'fill': value}

def css(selector, **kw):
    return {'css': selector, **kw}

def settings(p, category):
    names = {'general': 'General', 'connection': 'Connection', 'network': 'Network', 'recovery': 'Keys & recovery', 'maintenance': 'VPS maintenance'}
    return [click('Settings'), click(names[category])]

def mutate(expression):
    return {'js': expression}

def patch(**state):
    return {'patch': state}

def scenarios(p):
    cases = []

    def add(family, name, actions=None, state=None, expand=False, expect=None):
        item = {'family': family, 'id': name, 'description': name.replace('-', ' ').capitalize(), 'actions': deepcopy(actions or []), 'state': deepcopy(state or {}), 'expand': expand}
        if expect:
            item['expect'] = expect
        cases.append(item)
        return item

    def variant(family, name, base, changes, actions=None, expand=True):
        add(family, name, base + (actions or []), changes, expand)
    desktop = True
    add('home', 'connected-home', expand=True)
    add('home', 'disconnected-home', state={'connected': False}, expand=True)
    status = 'local'
    variants = {'connecting': {'state': 'connecting'}, 'connection-interrupted': {'state': 'degraded', 'error': 'The VPN handshake timed out.'}, 'recovering-connection': {'state': 'degraded', 'recovery_in_progress': True, 'recovering': True, 'persistence_state': 'recovering', 'auto_reconnect_enabled': True, 'kill_switch_enabled': True, 'kill_switch_state': 'blocking'}, 'protection-verified': {'kill_switch_enabled': True, 'kill_switch_state': 'armed', 'auto_reconnect_enabled': True, 'always_on': True, 'lockdown_enabled': True}, 'protection-state-unavailable': {'supervisor_status_known': False, 'protection_status_known': False}, 'no-recent-handshake': {'handshake_recent': False}, 'no-traffic-measurements': {'byte_counters_available': False, 'traffic_metrics_supported': False, 'rx_bytes': 0, 'tx_bytes': 0, 'counter_epoch': None, 'tunnel_uptime_seconds': None}, 'ipv6-tunneled': {'ipv6_blocked': False, 'ipv6_tunneled': True}, 'selected-routes': {'routing_mode': 'selected_routes', 'included_routes': ['198.51.100.0/24'], 'allow_lan': True}, 'selected-applications': {'routing_mode': 'selected_applications', 'application_mode': 'include'}, 'mtu-manual': {'mtu': {'policy': {'mode': 'manual', 'value': 1280}, 'configured': 1280, 'outcome': 'measured'}, 'configured_mtu': 1280}, 'quality-packet-loss': {'transport_quality': {'sample': {'transport': 'direct_udp', 'probes_sent': 8, 'probes_received': 5, 'latency_micros': 228000, 'jitter_micros': 57000}, 'selection': 'observing', 'candidates_checked': 3}}, 'quality-unavailable': {'transport_quality_supported': False, 'transport_quality': None}}
    for name, v in variants.items():
        add('home', name + '-home', state={status: v}, expand=True)
    for transport in ['obfuscated_udp', 'tls_like', 'tcp_fallback']:
        add('home', transport.replace('_', '-') + '-connected', state={status: {'transport': transport}, 'remote': {'transport': transport}}, expand=True)
    add('home', 'local-status-unavailable', state={'errors': {'localStatus': ERROR}}, expand=True)
    add('home', 'connect-operation-failed', [click('Connect')], {'connected': False, 'errors': {'connectWithPolicy': ERROR}}, True)
    add('home', 'connect-operation-in-progress', [click('Connect')], {'connected': False, 'holds': ['connectWithPolicy']})
    add('home', 'disconnect-operation-in-progress', [click('Disconnect')], {'holds': ['disconnect']})
    add('home', 'disconnect-operation-failed', [click('Disconnect')], {'errors': {'disconnect': ERROR}})
    for name, v in {'metrics-reconnecting': {'errors': {'serverStatus': ERROR}}, 'metrics-polling': {'streamMode': 'polling'}, 'server-high-resource-usage': {'remote': {'cpu_usage_basis_points': 9870, 'memory_used_bytes': 1900000000, 'disk_used_bytes': 97000000000}}, 'dns-service-unhealthy': {'remote': {'dns_healthy': False}}, 'server-interface-down': {'remote': {'interface_up': False}}, 'device-rotation-pending': {'pendingRotation': True}, 'local-component-update-required': {'componentUpdate': True}}.items():
        add('home', name, state=v, expand=True)
    for method in ['clientPlatform', 'listServers']:
        add('startup', 'loading-' + method.lower(), state={'holds': [method]})
        add('startup', 'error-' + method.lower(), state={'errors': {method: ERROR}})
    cats = ['general', 'connection', 'network', 'recovery', 'maintenance']
    for cat in cats:
        base = [click('Settings')] if cat == 'index' else settings('desktop', cat)
        add('settings', cat + '-settings', base, expand=True)
        if cat not in ['general', 'index']:
            add('settings', cat + '-settings-disconnected', base, {'connected': False}, True)
    for role in ['admin', 'member']:
        for cat in ['network', 'recovery', 'maintenance']:
            add('settings', cat + '-settings-' + role, settings('desktop', cat), {'role': role}, True)
    general = settings('desktop', 'general')
    for control in ['Interface animations'] + ['Connection notifications', 'Start on system startup', 'Launch minimized', 'Close to tray']:
        add('general', control.lower().replace(' ', '-') + '-enabled', general + [css('input[aria-label="' + control + '"]', check=True)], expand=True)
    add('general', 'preferences-load-failed', general, {'errors': {'getAppPreferences': ERROR}}, True)
    add('general', 'preferences-save-failed', general + [css('input[aria-label="Interface animations"]', check=True)], {'errors': {'setAppPreferences': ERROR}}, True)
    for perm in ['granted', 'denied', 'unknown']:
        add('general', 'notification-permission-' + perm, general, {'appPreferences': {'preferences': {'notifications': True}, 'notification_permission': perm}}, True)
    connection = settings('desktop', 'connection')
    for transport in ['automatic', 'direct_udp', 'obfuscated_udp', 'tls_like', 'tcp_fallback']:
        add('connection', 'saved-transport-' + transport.replace('_', '-'), connection, {'preferences': {'transport': transport}}, True)
    for network in ['normal', 'restricted', 'extreme']:
        add('connection', 'saved-network-' + network, connection, {'preferences': {'network_profile': network}}, True)
    for name, pol in [('kill-switch', {'kill_switch': True}), ('automatic-reconnect', {'automatic_reconnect': True}), ('connect-on-startup', {'connect_on_startup': True}), ('all-protection-preferences', {'kill_switch': True, 'automatic_reconnect': True, 'connect_on_startup': True})]:
        add('connection', name + '-saved', connection, {'preferences': {'policy': pol}}, True)
    for kind in ['loading', 'error']:
        add('connection', 'preferences-' + kind, connection, {'holds': ['getConnectionPreferences']} if kind == 'loading' else {'errors': {'getConnectionPreferences': ERROR}}, True)
    dirty = [css('input[aria-label="Kill switch"]', check=True)]
    add('connection', 'unsaved-connection-preferences', connection + dirty, expand=True)
    add('connection', 'saving-connection-preferences', connection + dirty + [click('Save preferences')], {'holds': ['setConnectionPreferences']}, True)
    add('connection', 'connection-preferences-save-failed', connection + dirty + [click('Save preferences')], {'errors': {'setConnectionPreferences': ERROR}}, True)
    add('connection', 'connection-preferences-saved', connection + dirty + [click('Save preferences')], expand=True)
    network = settings('desktop', 'network')
    for mode in ['full_tunnel', 'selected_routes', 'selected_applications']:
        add('routing', 'saved-routing-' + mode.replace('_', '-'), network, {'preferences': {'routing': {'mode': mode, 'included_routes': ['198.51.100.0/24', '203.0.113.40/32']}}}, True)
    add('routing', 'local-network-access-enabled', network, {'preferences': {'routing': {'allow_lan': True}}}, True)
    for backend in ['linux_namespace', 'windows_bind_redirect']:
        add('routing', 'application-routing-' + backend.replace('_', '-'), network, {'preferences': {'routing': {'mode': 'selected_applications'}}, 'local': {'routing_mode': 'selected_applications', 'application_routing_backend': backend}}, True)
    add('routing', 'application-routing-unavailable', network, {'local': {'application_routing_supported': False}}, True)
    for mtu in [1280, 1360, 1420]:
        add('routing', 'manual-packet-size-' + str(mtu), connection, {'preferences': {'manual_mtu': mtu}}, True)
    devices = [click('Devices')]
    add('devices', 'owner-device-list', devices, expand=True)
    for role in ['admin', 'member']:
        add('devices', role + '-device-list', devices, {'role': role}, True)
    add('devices', 'disconnected-device-list', devices, {'connected': False})
    add('devices', 'device-list-loading', devices, {'holds': ['membership']})
    add('devices', 'device-list-failed', devices, {'errors': {'membership': ERROR}})
    for value, name in [('Android', 'search-matching-device'), ('10.77.0.3', 'search-tunnel-address'), ('No matching device', 'search-no-results')]:
        add('devices', name, devices + [css('input[type="search"]', fill=value)])
    for name in ['My Linux desktop', 'Morgan’s laptop', 'Android phone', 'Work laptop']:
        add('devices', 'details-' + name.lower().replace(' ', '-').replace('’', ''), devices + [click(name, False)], expand=True)
        add('devices', 'menu-' + name.lower().replace(' ', '-').replace('’', ''), devices + [click('Actions for ' + name)])
    add('devices', 'all-device-details-expanded', devices + [mutate("document.querySelectorAll('.device-row-summary').forEach(el=>el.click())")], expand=True)
    add('devices', 'older-vps-device-capabilities', devices, {'configuration': {'member_lifecycle_enabled': False, 'member_policies_enabled': False, 'reusable_invitations_enabled': False}}, True)
    inv = devices + [click('Invite member')]
    add('invitations', 'new-member-invitation', inv, expand=True)
    add('invitations', 'new-admin-invitation', inv + [fill('Access level', 'admin')], expand=True)
    for lifetime in ['86400', '604800']:
        add('invitations', 'invitation-expires-' + ('24-hours' if lifetime == '86400' else '7-days'), inv + [fill('Expires after', lifetime)], expand=True)
    add('invitations', 'reusable-invitation-10-joins', inv + [fill('Number of joins', '10')], expand=True)
    add('invitations', 'legacy-invitation-name-fields', inv, {'configuration': {'recipient_names_enabled': False}}, True)
    legacy = [fill('Device name', 'Android tablet')]
    add('invitations', 'legacy-invitation-ready-to-create', inv + legacy, {'configuration': {'recipient_names_enabled': False}}, True)
    for kind in ['loading', 'error']:
        add('invitations', 'invitation-creation-' + kind, inv + [click('Create single-use code')], {'holds': ['createInvitation']} if kind == 'loading' else {'errors': {'createInvitation': ERROR}}, True)
    result = inv + [click('Create single-use code')]
    add('invitations', 'invitation-created-qr-and-code', result, expand=True)
    add('invitations', 'invitation-enlarged-qr', result + [click('Enlarge invitation QR code')])
    add('invitations', 'reusable-invitation-created', inv + [fill('Number of joins', '10'), click('Create reusable code')], expand=True)
    for target in ['My Linux desktop', 'Morgan’s laptop', 'Android phone']:
        add('invitations', 'add-device-' + target.lower().replace(' ', '-').replace('’', ''), devices + [click('Actions for ' + target), click('Add device', False)], expand=True)
    empty = {'empty': True}
    for mode in ['My VPS', 'Invitation', 'Backup', 'Recovery key']:
        add('onboarding', 'first-launch-' + mode.lower().replace(' ', '-'), [click(mode)] if mode != 'My VPS' else [], empty, True)
    add('onboarding', 'add-another-vps', [click('Add server')], expand=True)
    recovery = settings('desktop', 'recovery')
    maintenance = settings('desktop', 'maintenance')
    for name, base in [('Export device backup', recovery), ('Rotate device keys', recovery), ('Move devices to a new VPS address', maintenance), ('Remove saved server or uninstall SirinVPN', maintenance)]:
        add('dialogs', name.lower().replace(' ', '-'), base + [click(name, False)], expand=True)
    for name, base in [('Back up VPS', recovery), ('Restore or migrate VPS', recovery), ('Update VPS software', maintenance), ('Repair VPS configuration', maintenance)]:
        family = {'Back up VPS': 'vps-backup', 'Restore or migrate VPS': 'vps-restore', 'Update VPS software': 'vps-updates', 'Repair VPS configuration': 'vps-repair'}[name]
        steps = base + [click(name, False)]
        add(family, 'review-' + family + '-while-connected', steps, expand=True)
        add(family, 'review-' + family + '-disconnected', steps, {'connected': False}, True)
        add(family, family + '-ssh-details', steps + [click('Continue to VPS setup')], {'connected': False}, True)
    add('app-updates', 'desktop-app-update-dialog', general + [click('App updates')], expand=True)
    add('app-updates', 'desktop-local-component-review', general + [click('Review local component')], expand=True)
    from workflows import workflows
    workflows('desktop', add)
    from extra_states import extra_states
    extra_states('desktop', add)
    from current_states import current_states
    current_states(add)
    for case in cases:
        checks = case.setdefault('assertions', [])
        if case['family'] == 'startup' and case['state'].get('errors'):
            checks.append({'selector': '[role=alert]'})
        if case['family'] == 'devices' and case['id'].startswith('menu-'):
            checks.append({'selector': '[role=menu]', 'scroll': False})
        if case['family'] == 'port-forwarding' and any((word in case['id'] for word in ['invalid', 'reserved', 'out-of-range'])):
            checks.append({'selector': '.field-error'})
    return cases
