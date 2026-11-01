"""States the original catalog never reached: features added after it, Android-only screens and data extremes.

full_capture.py's message-coverage report lists the UI strings no state shows; each block below closes one gap.
A case may carry `forms`: the original scenarios that drive desktop-only controls are limited to the desktop.
"""
from scenarios import click, fill, css, settings, patch, mutate, DID, ERROR
from workflows import check

NTFY = 'https://ntfy.example/sirin-alerts'
BOTH = ('desktop', 'mobile')
# Startup, tray, window, Wi-Fi, SSH agent, app launching and desktop installers exist only on the desktop.
DESKTOP_ONLY = {'launch-minimized-enabled', 'start-on-system-startup-enabled', 'close-to-tray-enabled', 'startup-service-status-unavailable'}
DESKTOP_FAMILIES = {'wifi'}
DESKTOP_CONTROLS = {'SSH agent', 'Review component', 'Program', 'Launch arguments', 'Restore AppImage', 'Connect and activate', 'Check for updates', 'Copy VPN address', 'Kill switch', 'Enlarge invitation QR code', 'Enlarge recovery key QR code'}
# The first-launch choices: the original desktop segmented labels, and the list titles both layouts now share.
MODES = {'My VPS': 'Set up my VPS', 'Invitation': 'Use an invitation', 'Backup': 'Restore a backup', 'Recovery key': 'Use a recovery key'}
SET_UP = {'text': 'Set up my VPS', 'exact': False, 'or': {'text': 'My VPS'}, 'optional': True}


def mentions(action, names):
    return any(str(action.get(key, '')) in names for key in ('text', 'label')) or any(f'"{name}"' in str(action.get('css', '')) for name in names)


def adapt(case):
    """Make an original desktop scenario drive the Android layout too, or limit it to the desktop."""
    actions = case['actions']
    if case['id'] in DESKTOP_ONLY or case['family'] in DESKTOP_FAMILIES or any(mentions(a, DESKTOP_CONTROLS) for a in actions):
        case['forms'] = ('desktop',)
    onboarding = case['state'].get('empty') or any(a.get('text') == 'Add server' for a in actions)
    for index, action in enumerate(actions):
        if onboarding and action.get('text') in MODES and action.get('exact', True):
            actions[index] = {'text': MODES[action['text']], 'exact': False, 'or': dict(action)}
        if action.get('text') == 'Add server' and index == 0:
            actions.insert(0, {'text': 'Servers'})
        # The VPN address copy button lives in the collapsed Device details on Home.
        if action.get('text') == 'Copy VPN address' and not (index and actions[index - 1].get('details')):
            actions.insert(index, {'details': 'open'})
        if action.get('text') == 'Access policy' and index and actions[index - 1].get('text') == 'Family':
            actions.insert(index, {'text': 'Member actions for Family', 'android': True})
    # Provisioning steps that start on the desktop's default form first pick "Set up my VPS" where a choice list shows.
    if onboarding and actions and not any(a.get('text') in MODES.values() or a.get('or', {}).get('text') in MODES for a in actions[:3]):
        first = 2 if actions[0].get('text') == 'Servers' else 0
        if len(actions) > first and actions[first].get('text') not in ('App settings', 'Check for updates'):
            actions.insert(first, dict(SET_UP))
MANY_DEVICES = """const s=window.__catalog.state;s.members.members.push(...Array.from({length:6},(_,m)=>({id:'bulk-'+m,name:['Grandparents','Studio','Office','Lake house','Garage','Guest room'][m]+' — a long member name that wraps',role:'member',administrator:m===0,policy:s.members.members[2].policy,devices:Array.from({length:5},(_,d)=>({id:'bulk-'+m+'-'+d,name:'Device '+(d+1)+' with an unusually long descriptive name',client_tunnel_address:'10.77.'+(m+1)+'.'+(d+10),identity_fingerprint:s.members.members[0].devices[0].identity_fingerprint,recent_handshake:d%2===0,wireguard_only:d===4}))})));"""
ROUTES = """const d=window.__catalog.state.members.members[0].devices[0];d.subnet_routes=['192.168.1.0/24','10.20.0.0/24'];d.inactive_subnet_routes=['10.20.0.0/24'];"""
PAIRS = "window.__catalog.state.members.device_pairs=[{device_id:'phone-device',peer_device_id:'admin-device'},{device_id:'phone-device',peer_device_id:'" + DID + "',one_way:true},{device_id:'laptop-device',peer_device_id:'phone-device',one_way:true}];"


def coverage_states(cases):
    for case in cases:
        adapt(case)
        # Android opens action menus as a bottom sheet (a dialog) instead of a popup menu.
        for assertion in case.get('assertions', []):
            if assertion.get('selector') == '[role=menu]':
                assertion['selector'] = '[role=menu],[role=dialog]'

    def add(family, name, actions=(), state=None, forms=BOTH, required=()):
        case = {'family': family, 'id': name, 'description': name.replace('-', ' ').capitalize(), 'actions': list(actions),
                'state': state or {}, 'expand': True, 'forms': forms}
        if required:
            case['required_calls'] = list(required)
        cases.append(case)

    def outcomes(family, name, base, last, method, state=None):
        add(family, name + '-in-progress', base + [patch(holds=[method]), last], state, required=[method])
        add(family, name + '-failed', base + [patch(errors={method: ERROR}), last], state, required=[method])
        add(family, name + '-completed', base + [last], state, required=[method])

    # Settings index and per-role home screens.
    add('settings', 'settings-index', [click('Settings')])
    for role in ['admin', 'member']:
        add('home', role + '-connected-home', state={'role': role})
        add('home', role + '-disconnected-home', state={'role': role, 'connected': False})
        add('settings', 'general-settings-' + role, settings('', 'general'), {'role': role})
        add('settings', 'connection-settings-' + role, settings('', 'connection'), {'role': role})

    # VPS alerts (Owner, maintenance settings).
    maintenance = settings('', 'maintenance')
    saved = {'alerts': {'policy': {'format': 'ntfy', 'alert_url': NTFY}}}
    add('vps-alerts', 'alerts-address-entered', maintenance + [fill('Alert address', NTFY)])
    add('vps-alerts', 'alerts-address-invalid', maintenance + [fill('Alert address', 'http://user@alerts.example/topic'), fill('Heartbeat address', 'not an address')])
    add('vps-alerts', 'alerts-webhook-format', maintenance + [check('Webhook')])
    outcomes('vps-alerts', 'save-alerts', maintenance + [fill('Alert address', NTFY)], click('Save alerts'), 'updateAlerts')
    add('vps-alerts', 'alerts-test-sent', maintenance + [click('Send test alert')], saved, required=['sendTestAlert'])
    add('vps-alerts', 'alerts-test-rejected', maintenance + [click('Send test alert')], {**saved, 'alertTest': {'failure': 'rejected', 'http_status': 403}}, required=['sendTestAlert'])
    add('vps-alerts', 'alerts-delivery-failing', maintenance, {'alerts': {'policy': {'format': 'webhook', 'alert_url': NTFY, 'heartbeat_url': NTFY + '/beat'}, 'status': {'checked_at_unix': 1900000000, 'alert_failure': 'connection', 'heartbeat_failure': 'address'}}})
    add('vps-alerts', 'alerts-healthy', maintenance, {'alerts': {'policy': {'format': 'ntfy', 'alert_url': NTFY, 'heartbeat_url': NTFY + '/beat'}, 'status': {'checked_at_unix': 1900000000, 'alert_sent_at_unix': 1899990000, 'heartbeat_sent_at_unix': 1900000000}}})
    add('vps-alerts', 'alerts-unsupported-vps', maintenance, {'configuration': {'alerts_enabled': False}})
    add('vps-alerts', 'alerts-load-failed', maintenance, {'errors': {'alertSettings': ERROR}})
    add('vps-alerts', 'alerts-loading', maintenance, {'holds': ['alertSettings']})

    # DNS blocking (network settings).
    network = settings('', 'network')
    enable = [check('Block ads and trackers'), check('Light list')]
    add('dns-blocking', 'blocking-enabled-unsaved', network + enable)
    add('dns-blocking', 'blocking-invalid-lists', network + enable + [fill('Other blocklists', 'lists.example/hosts\nftp://lists.example'), fill('Never block', 'not a domain!')])
    outcomes('dns-blocking', 'save-blocking', network + enable, click('Save blocking'), 'updateDnsBlocklist')
    active = {'policy': {'enabled': True, 'sources': ['https://lists.example/light.txt'], 'allowlist': ['example.com']}, 'status': {'active': True, 'domain_count': 184312, 'updated_at_unix': 1900000000}}
    add('dns-blocking', 'blocking-active', network, {'blocklist': active})
    add('dns-blocking', 'blocking-pending', network, {'blocklist': {**active, 'pending': True}})
    for failure in ['download', 'format', 'too_many_domains', 'resolver']:
        add('dns-blocking', 'blocking-failure-' + failure.replace('_', '-'), network, {'blocklist': {**active, 'status': {**active['status'], 'failure': failure}}})
    add('dns-blocking', 'blocking-unsupported-vps', network, {'configuration': {'dns_blocklist_management_enabled': False}})
    add('dns-blocking', 'blocking-load-failed', network, {'errors': {'dnsBlocklistSettings': ERROR}})
    add('dns-blocking', 'blocking-member-view', network, {'role': 'member', 'blocklist': active})

    # Speed test inside the diagnostics dialog.
    diagnostics = maintenance + [click('Run diagnostics')]
    outcomes('speed-test', 'speed-test', diagnostics, click('Run speed test'), 'speedTest')

    # Troubleshooter ("Can't connect?").
    # The hero offers the guide after a failed connection or while the tunnel is degraded.
    troubleshoot = [click('Can’t connect? Find out why')]
    failed = {'connected': False, 'errors': {'connectWithPolicy': ERROR}}
    add('troubleshooter', 'troubleshooter-first-step', [click('Connect')] + troubleshoot, failed, required=['diagnostics'])
    add('troubleshooter', 'troubleshooter-checking', [click('Connect'), patch(holds=['diagnostics'])] + troubleshoot, failed)
    add('troubleshooter', 'troubleshooter-failures', [click('Connect')] + troubleshoot, {**failed, 'diagnosticPreset': 'failures'})
    add('troubleshooter', 'troubleshooter-second-step', [click('Connect')] + troubleshoot + [click('Next')], {**failed, 'diagnosticPreset': 'failures'})
    add('troubleshooter', 'troubleshooter-from-degraded', troubleshoot, {'local': {'state': 'degraded', 'error': 'The VPN handshake timed out.'}, 'diagnosticPreset': 'failures'})
    add('troubleshooter', 'troubleshooter-from-settings', maintenance + [click('Troubleshoot')], {'connected': False})

    # Device pairs and shared local networks (devices menu).
    devices = [click('Devices')]
    pairs = devices + [click('Actions for Android phone'), click('Device pairs')]
    add('device-pairs', 'pairs-none', pairs)
    add('device-pairs', 'pairs-existing', [mutate(PAIRS)] + pairs)
    outcomes('device-pairs', 'add-pair', pairs + [fill('Direction', 'starts')], click('Add pair'), 'setDevicePair')
    add('device-pairs', 'remove-pair', [mutate(PAIRS)] + pairs + [click('Remove')], required=['removeDevicePair'])
    routes = devices + [click('Actions for My Linux desktop'), click('Local networks')]
    add('local-networks', 'local-networks-empty', routes)
    add('local-networks', 'local-networks-entered', routes + [fill('Networks', '192.168.1.0/24\n10.20.0.0/24')])
    add('local-networks', 'local-networks-invalid', routes + [fill('Networks', '192.168.0.0/8\nnot a network')])
    outcomes('local-networks', 'save-local-networks', routes + [fill('Networks', '192.168.1.0/24')], click('Save networks'), 'updateDeviceSubnetRoutes')
    add('local-networks', 'shared-networks-on-device-list', [mutate(ROUTES)] + devices + [click('My Linux desktop', False)])

    # Hetzner VPS creation.
    for where, base, state in [('first-launch', [], {'empty': True}), ('add-server', [click('Servers'), click('Add server')], {})]:
        hetzner = base + [click('New Hetzner VPS', **{'or': click('Create a Hetzner server', False)})]
        add('hetzner', where + '-hetzner-token', hetzner, state)
        plans = hetzner + [fill('Hetzner Cloud API token', 'example-hetzner-token'), click('Show prices')]
        if where == 'add-server':
            add('hetzner', where + '-hetzner-plans', plans, state, required=['hetznerCatalog'])
            continue
        add('hetzner', 'hetzner-token-entered', hetzner + [fill('Hetzner Cloud API token', 'example-hetzner-token')], state)
        add('hetzner', 'hetzner-plans-loading', hetzner + [fill('Hetzner Cloud API token', 'example-hetzner-token'), patch(holds=['hetznerCatalog']), click('Show prices')], state)
        add('hetzner', 'hetzner-plans-failed', hetzner + [fill('Hetzner Cloud API token', 'example-hetzner-token'), patch(errors={'hetznerCatalog': ERROR}), click('Show prices')], state)
        add('hetzner', 'hetzner-plans', plans, state, required=['hetznerCatalog'])
        add('hetzner', 'hetzner-other-location', plans + [fill('Location', 'ash')], state)
        create = click('Create server for', False)
        add('hetzner', 'hetzner-creating', plans + [patch(holds=['createHetznerServer']), create], state, required=['createHetznerServer'])
        add('hetzner', 'hetzner-create-failed', plans + [patch(errors={'createHetznerServer': ERROR}), create], state, required=['createHetznerServer'])
        add('hetzner', 'hetzner-waiting', plans + [patch(holds=['waitHetznerServer']), create], state, required=['waitHetznerServer'])
        failed = plans + [patch(errors={'waitHetznerServer': ERROR}), create]
        add('hetzner', 'hetzner-not-ready', failed, state, required=['waitHetznerServer'])
        add('hetzner', 'hetzner-kept', failed + [click('Keep server')], state)
        add('hetzner', 'hetzner-deleted', failed + [click('Delete this server')], state, required=['deleteHetznerServer'])
        add('hetzner', 'hetzner-ready-to-install', plans + [create], state, required=['waitHetznerServer'])

    # A new VPS with password sign-in: the one SSH method both layouts offer.
    # The saved-login lookup after a host change resets secrets typed within ~250 ms; a person is slower.
    setup = [dict(SET_UP), fill('IP address or hostname', 'vpn.example.com'), {'wait': 600}, fill('SSH password', 'example-password')]
    verified = setup + [click('Verify server'), click('Fingerprint matches')]
    empty = {'empty': True}
    add('provisioning', 'password-details-ready', setup, empty)
    add('provisioning', 'password-fingerprint-review', setup + [click('Verify server')], empty)
    add('provisioning', 'password-network-review', verified, empty)
    outcomes('provisioning', 'password-install', verified, click('Install SirinVPN'), 'provisionServer', empty)

    # Android sub-pages and the server picker.
    mobile = ('mobile',)
    add('android', 'connection-subpage', [click('Connection Method', False)], forms=mobile)
    add('android', 'connection-subpage-disconnected', [click('Connection Method', False)], {'connected': False}, forms=mobile)
    add('android', 'details-subpage', [click('Connection details', False)], forms=mobile)
    add('android', 'details-subpage-disconnected', [click('Connection details', False)], {'connected': False}, forms=mobile)
    add('android', 'server-picker', [click('Server: My private VPS. Change server')], {'profileCount': 4}, forms=mobile)
    add('android', 'server-picker-long-names', [click('Server: ', False)], {'profileCount': 12, 'longNames': True}, forms=mobile)
    add('android', 'home-long-server-name', [], {'longNames': True}, forms=mobile)

    # Scheduled VPS backups (Owner, Keys & recovery).
    schedule = settings('', 'recovery') + [click('Scheduled backups', False)]
    planned = {'server_id': '123e4567-e89b-42d3-a456-426614174000', 'folder': '/home/demo/Backups/SirinVPN', 'keep': 7, 'interval_days': 7, 'enabled_at': 1899000000,
               'last_success': None, 'last_failure': None, 'due': True, 'stale': False}
    add('vps-schedule', 'schedule-off', schedule)
    add('vps-schedule', 'schedule-filled', schedule + [click('Choose folder'), fill('Frequency', '7'), fill('Backups to keep', '5'),
        fill('Backup password', 'Screenshot-example-2026'), fill('Repeat password', 'Screenshot-example-2026')], {'connected': False})
    for name, extra in [('pending', {}), ('healthy', {'last_success': 1899990000, 'due': False}),
                        ('overdue', {'last_success': 1890000000, 'stale': True}),
                        ('failed', {'last_failure': {'at': 1899990000, 'message': 'The VPS could not be reached over SSH.'}})]:
        add('vps-schedule', 'schedule-' + name, schedule, {'vpsBackupSchedules': [{**planned, **extra}]})
    add('vps-schedule', 'schedule-overdue-home-notice', [], {'vpsBackupSchedules': [{**planned, 'last_success': 1890000000, 'stale': True}]})
    outcomes('vps-schedule', 'back-up-now', schedule, click('Back up now'), 'runScheduledVpsBackup', {'connected': False, 'vpsBackupSchedules': [planned]})
    add('vps-schedule', 'schedule-turned-off', schedule + [click('Turn off')], {'vpsBackupSchedules': [planned]}, required=['disableVpsBackupSchedule'])

    # WireGuard-only devices (iPhone, routers) from the Devices page.
    wireguard = devices + [click('Add WireGuard device')]
    add('wireguard-devices', 'wireguard-device-empty', wireguard)
    filled = wireguard + [fill('Member name', 'Router'), fill('Device name', 'Home router')]
    add('wireguard-devices', 'wireguard-device-filled', filled)
    outcomes('wireguard-devices', 'create-wireguard-device', filled, click('Create configuration'), 'createWireGuardDevice')

    # Data extremes.
    add('extremes', 'many-members-and-devices', [mutate(MANY_DEVICES)] + devices)
    add('extremes', 'many-devices-expanded', [mutate(MANY_DEVICES)] + devices + [mutate("document.querySelectorAll('.device-row-summary').forEach(el=>el.click())")])
    add('extremes', 'only-own-device', [mutate("const s=window.__catalog.state;s.members.members=s.members.members.slice(0,1);")] + devices)
    add('extremes', 'long-names-home', [], {'longNames': True})
    add('extremes', 'long-names-settings', settings('', 'maintenance'), {'longNames': True})
    add('extremes', 'twelve-servers-home', [], {'profileCount': 12})
    for case in cases:
        # The Android runtime has no command to export WireGuard configurations (AccessPanel hides the action).
        if case['family'] == 'wireguard-devices':
            case['forms'] = ('desktop',)
    return cases
