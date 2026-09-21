"""Additional visible branches found in the current desktop source inventory."""
from scenarios import click, fill, css, settings, patch, mutate, ID, DID, ERROR
from workflows import check, PASS, SOURCE, KEY


def current_states(add):
    general, connection, network, recovery, maintenance = [settings('desktop', c) for c in ['general', 'connection', 'network', 'recovery', 'maintenance']]
    devices = [click('Devices')]
    empty = {'empty': True}

    def case(family, name, actions=(), state=None, expect=None):
        row = add(family, name, list(actions), state, True, expect)
        row['added_inventory'] = '2026-09-20'
        return row

    def outcomes(family, name, actions, method, state=None):
        for kind, change in [('in-progress', {'holds': [method]}), ('failed', {'errors': {method: ERROR}}), ('completed', {})]:
            row = case(family, name + '-' + kind, list(actions[:-1]) + [patch(**change), actions[-1]], state)
            row['required_calls'] = [method]

    for name, state in [
        ('local-status-stale', {'errors': {'localStatus': ERROR}}),
        ('local-status-loading', {'holds': ['localStatus']}),
        ('other-server-active', {'local': {'server_id': 'another-server'}}),
        ('unverified-application-routing', {'local': {'routing_mode': 'selected_applications', 'application_routing_ready': False}}),
        ('ipv6-protection-unavailable', {'local': {'ipv6_blocked': False, 'ipv6_tunneled': False}}),
        ('handshake-without-probe-replies', {'local': {'transport_quality': {'sample': {'probes_received': 0}}}}),
        ('https-transport-connected', {'profile': {'tls_like': {'https': {'server_name': 'vpn.example.com', 'path': '/connect'}}}, 'local': {'transport': 'tls_like'}}),
        ('maximized-titlebar', {'maximized': True}),
    ]:
        case('home', name, state=state)
    for reason in ['confirmed_failure', 'quality_improvement', 'rollback']:
        case('measurements', 'transport-switch-' + reason.replace('_', '-'), state={'local': {'transport_quality': {'last_switch_reason': reason}}})
    outcomes('home', 'resume-paused-connection', [click('Reconnect')], 'resume', {'local': {'state': 'degraded', 'waiting_for_user': True}})
    for fail in [False, True]:
        case('home', 'endpoint-copy-' + ('failed' if fail else 'completed'), [click('Copy VPN endpoint')], {'clipboardError': fail}, 'Copy failed' if fail else 'Copied')

    case('onboarding', 'first-launch-app-settings', [click('App settings')], empty)
    case('onboarding', 'first-launch-app-updates', [click('Check for app updates')], empty)
    for tab in ['Invitation', 'Backup', 'Recovery key']:
        case('onboarding', 'add-server-' + tab.lower().replace(' ', '-'), [click('Add server'), click(tab)])
    for name, state in [('startup-registration-unavailable', {'appPreferences': {'startup_available': False}}), ('system-tray-unavailable', {'appPreferences': {'tray_available': False}}), ('app-preferences-loading', {'holds': ['getAppPreferences']})]:
        case('general', name, general, state)
    case('general', 'preference-saving', general + [check('Interface animations')], {'holds': ['setAppPreferences']}, 'Saving')
    for permission in ['denied', 'unknown']:
        case('general', 'notification-request-' + permission, general + [check('Connection notifications')], {'responses': {'requestNotificationPermission': permission}}, 'Notifications are blocked')
    outcomes('general', 'send-test-notification', general + [click('Test notification')], 'testNotification', {'appPreferences': {'preferences': {'notifications': True}}})

    for status in ['trusted', 'connecting', 'session_active', 'needs_attention', 'needs_authorization']:
        case('wifi', 'automation-' + status.replace('_', '-'), general, {'wifi': {'policy': {'enabled': True, 'server_id': ID}, 'automation_status': status}})
    case('wifi', 'network-identity-unavailable', general, {'wifi': {'current_network_token': None, 'can_trust_current': False}})
    case('wifi', 'network-changed-before-trust', general + [patch(wifi={'current_network_token': 'new-network'}), {'wait': 5100}], expect='The network changed')
    outcomes('wifi', 'enable-wifi-automation', general + [check('Connect on Wi-Fi not marked trusted')], 'setWifiPolicy')
    outcomes('wifi', 'trust-current-network', general + [fill('Network name', 'Home Wi-Fi'), click('Trust current Wi-Fi')], 'trustCurrentWifi')
    outcomes('wifi', 'remove-trusted-network', general + [click('Remove trust', False)], 'forgetTrustedWifi', {'wifi': {'trusted_networks': [{'id': 'home', 'label': 'Home Wi-Fi'}]}})
    trusted = {'current_network': 'trusted_wifi', 'current_network_token': 'home-network', 'trusted_networks': [{'id': 'home-network', 'label': 'Wi-Fi exception'}, {'id': 'office-network', 'label': 'Wi-Fi exception'}], 'network_names': {'home-network': 'Home hotspot', 'office-network': 'Office hotspot'}}
    case('wifi', 'os-wifi-names-existing-trust-records', general, {'wifi': trusted}, 'Office hotspot')
    case('wifi', 'os-wifi-names-custom-labels', general, {'wifi': {**trusted, 'trusted_networks': [{'id': 'home-network', 'label': 'Family home'}, {'id': 'office-network', 'label': 'Work'}]}}, 'Label: Family home')
    case('wifi', 'os-wifi-names-unavailable', general, {'wifi': {**trusted, 'network_names': None}}, 'OS name unavailable')
    case('wifi', 'os-wifi-names-long-and-unicode', general, {'wifi': {**trusted, 'network_names': {'home-network': 'Ev ağı · Café / Home: 5 GHz', 'office-network': 'Office guest Wi-Fi · Second floor · Meeting rooms and shared workspace'}}})
    case('wifi', 'os-wifi-names-unbroken', general, {'wifi': {**trusted, 'network_names': {'home-network': 'W' * 32, 'office-network': 'Office hotspot'}}})
    case('wifi', 'os-wifi-name-network-change', general + [patch(wifi={'current_network_token': 'office-network', 'network_names': {'office-network': 'Office hotspot'}}), {'wait': 5100}], expect='Office hotspot')

    for name, state in [
        ('status-unknown', {'local': {'state': 'unknown'}}),
        ('service-status-unavailable', {'local': {'startup_service_enabled': None}}),
        ('saved-not-active', {'connected': False}),
        ('other-server-active', {'local': {'server_id': 'another-server'}}),
        ('service-server-unconfirmed', {'local': {'startup_service_enabled': True, 'connect_on_startup': False}}),
    ]:
        actions=connection + ([mutate('delete window.__catalog.state.local.startup_service_enabled'), {'wait':600}] if name=='service-status-unavailable' else [])
        case('connection', 'startup-' + name, actions, {**state, 'preferences': {'policy': {'connect_on_startup': True}}}, 'service status unavailable' if name=='service-status-unavailable' else None)
    outcomes('connection', 'activate-startup', connection + [click('Connect & activate startup')], 'connectWithPolicy', {'connected': False, 'preferences': {'policy': {'connect_on_startup': True}}})
    case('connection', 'unsupported-manual-transports', connection, {'preferences': {'transport': 'direct_udp'}, 'profile': {'obfuscated_udp': None, 'tcp_fallback': None, 'tls_like': None}})
    for mtu in [575, 1421]:
        case('measurements', 'invalid-manual-mtu-' + str(mtu), connection, {'preferences': {'manual_mtu': mtu}})
    case('measurements', 'ipv6-mtu-minimum', connection, {'profile': {'ipv6_tunnel_enabled': True}, 'preferences': {'manual_mtu': 1200}})
    case('measurements', 'mtu-component-unsupported', connection, {'local': {'mtu_detection_supported': False, 'mtu': None}})
    case('measurements', 'mtu-verified-configured-value', connection, {'local': {'mtu': {'suggested': 1420}}})
    for value, name in [('not-a-route', 'invalid-cidr'), ('', 'empty-selected-routes'), ('198.51.100.7/24', 'noncanonical-cidr')]:
        case('routing', name, network + [fill('IPv4 or IPv6 CIDRs', value), click('Save preferences')], {'preferences': {'routing': {'mode': 'selected_routes', 'included_routes': ['198.51.100.0/24']}}})
    appstate = {'preferences': {'routing': {'mode': 'selected_applications'}}, 'local': {'routing_mode': 'selected_applications'}}
    case('routing', 'application-launch-arguments', network + [click('Launch arguments'), fill('One argument per line', '--private-window\nhttps://example.com')], appstate)
    outcomes('routing', 'launch-application', network + [fill('Application executable', '/usr/bin/firefox'), click('Launch in VPN')], 'launchVpnApplication', appstate)
    case('routing', 'launched-command-already-finished', network + [fill('Application executable', '/usr/bin/true'), click('Launch in VPN')], {**appstate, 'responses': {'launchVpnApplication': {'process_id': 4242, 'completed': True}}})
    case('routing', 'windows-driver-unavailable', network, {'local': {'application_routing_backend': 'windows_bind_redirect', 'application_routing_supported': False}})

    member = devices + [click('Family', False), click('Access policy')]
    for actions, name in [([click('Add interval')], 'weekly-day-time-controls'), ([click('Add interval'), fill('Start 1', '22:00'), fill('End 1', '06:00')], 'overnight-weekly-access'), ([fill('Device limit', '0')], 'invalid-device-limit'), ([fill('Access expires', '2020-01-01T12:00')], 'expired-access-date')]:
        case('member-policy', name, member + actions, {'emptyMember': True})
    for method, label, state in [
        ('cancelInvitation', 'Cancel', {'activeInvitation': 'reusable'}),
        ('removePortForward', 'Close port', {'members': {'port_forwards': [{'protocol': 'tcp', 'public_port': 48080, 'device_id': DID, 'device_port': 8080}]}}),
    ]:
        base = devices + [{'details': 'open'}] if method == 'cancelInvitation' else network
        outcomes('invitations' if method == 'cancelInvitation' else 'port-forwarding', method, base + [click(label, False)], method, state)
    inv = devices + [click('Invite member')]
    case('invitations', 'invitation-access-policy-expanded', inv + [click('Member permissions and access times'), click('Add interval')])
    for joins in ['0', '101']:
        case('invitations', 'invalid-invitation-joins-' + joins, inv + [fill('Number of joins', joins)])

    setup = [fill('IP address or hostname', 'vpn.example.com'), click('SSH agent')]
    advanced = setup + [click('Advanced server configuration')]
    transport = advanced + [click('Public addresses, transport ports and HTTPS')]
    case('provisioning', 'https-transport-fields', transport + [check('Use HTTPS mode'), fill('HTTPS hostname', 'vpn.example.com')], empty)
    case('provisioning', 'https-certificate-import', transport + [check('Use HTTPS mode'), fill('HTTPS hostname', 'vpn.example.com'), fill('Certificate chain path', '/etc/ssl/vpn/fullchain.pem'), fill('Certificate private key path', '/etc/ssl/vpn/private.pem')], empty)
    case('provisioning', 'invalid-transport-port', transport + [fill('Direct UDP port', '53')], empty)
    replace = advanced + [check('Replace existing SirinVPN installation'), click('Verify VPS')]
    case('provisioning', 'replace-existing-installation-warning', replace, empty)
    outcomes('provisioning', 'inspect-vps-network', setup + [click('Verify VPS'), click('Fingerprint matches — inspect network')], 'inspectServerNetwork', empty)
    for mode in ['DNS over TLS', 'DNS over HTTPS']:
        case('dns', 'onboarding-' + mode.lower().replace(' ', '-'), advanced + [click(mode)], empty)
    for zones, name in [('office.home=10.20.0.53', 'private-split-zone'), ('corp.example=192.0.2.53#dns.example.com', 'tls-split-zone'), ('office.local=8.8.8.8', 'invalid-split-zone')]:
        case('dns', name, advanced + [fill('Split DNS zones', zones)], empty)
    dns = network + [click('Configure VPS DNS'), click('Continue to VPS setup')]
    case('dns', 'clear-private-records-review', dns + [click('Clear')], {'connected': False})
    case('dns', 'replace-private-records-filled', dns + [click('Replace'), fill('One DNS-name=IP record per line', 'nas.home=10.20.30.40\nserver.home=fd00::10')], {'connected': False})

    repair = maintenance + [click('Repair VPS configuration', False)]
    for name, state in [('pending-key-rotation', {'pendingRotation': True}), ('local-status-unknown', {'errors': {'localStatus': ERROR}}), ('traffic-block-active', {'local': {'kill_switch_enabled': True, 'kill_switch_state': 'blocking'}})]:
        case('vps-repair', 'maintenance-requires-' + name, repair, state)
    outcomes('vps-repair', 'disconnect-for-maintenance', repair + [click('Disconnect this computer')], 'disconnect')
    ssh = repair + [click('Continue to VPS setup')]
    saved = {'connected': False, 'savedLogin': {'username': 'admin', 'ssh_port': 2222, 'authentication': 'agent', 'private_key_path': None}}
    case('vps-repair', 'edit-saved-ssh-login', ssh + [click('Change login')], saved)
    outcomes('vps-repair', 'forget-saved-ssh-login', ssh + [click('Forget login')], 'forgetSshLogin', saved)

    recover = [click('Recovery key'), click('Open an encrypted recovery package'), fill('Package password', PASS), click('Open recovery package')]
    outcomes('owner-recovery', 'import-encrypted-recovery-package', recover, 'importRecoveryPackage', empty)
    case('recovery-keys', 'recovery-qr-expanded', recovery + [check('I understand that anyone holding this key'), click('Create recovery key'), click('Recovery QR code')])
    case('recovery-keys', 'recovery-package-password-mismatch', recovery + [check('I understand that anyone holding this key'), click('Create recovery key'), fill('Recovery package password', PASS), fill('Repeat package password', 'different-password')])
    created = recovery + [check('I understand that anyone holding this key'), click('Create recovery key')]
    case('recovery-keys', 'recovery-qr-enlarged', created + [click('Recovery QR code'), click('Enlarge recovery QR code')], expect='Scan recovery QR')
    case('recovery-keys', 'leave-unsaved-recovery-key-confirmation', created + [click('Home')], {'confirmResponse': False})
    case('recovery-keys', 'recovery-material-acknowledged', created + [check('I have saved this recovery key'), click('Finish recovery setup')], expect='Recovery material acknowledged')
    for fail in [False, True]:
        case('invitations', 'invitation-copy-' + ('failed' if fail else 'completed'), inv + [click('Create single-use code'), click('Copy code')], {'clipboardError': fail})
        case('recovery-keys', 'recovery-key-copy-' + ('failed' if fail else 'completed'), created + [click('Copy recovery key')], {'clipboardError': fail})
    endpoint = maintenance + [click('Move devices to a new VPS address', False)]
    outcomes('endpoint', 'retrieve-published-handoff', endpoint + [click('Retrieve from current VPS')], 'availableEndpointUpdate')
    case('endpoint', 'share-migration-disconnected', endpoint + [click('Share migration')], {'connected': False})
    case('endpoint', 'migration-pending-old-vps', endpoint, {'profile': {'pending_previous_endpoint': {'host': 'old-vps.example.com', 'wireguard_port': 51820}}})

    app = general + [click('App updates')]
    verified = app + [fill('Release source', SOURCE), click('Check and verify release')]
    case('app-updates', 'discard-verified-package-failed', verified + [click('Discard')], {'errors': {'discardReleaseUpdate': ERROR}})
    for kind in ['appimage', 'windows']:
        state = {'releaseCandidate': {'installer_kind': kind, 'debian_install_available': False, 'appimage_install_available': kind == 'appimage', 'windows_install_available': kind == 'windows', 'artifact_file_name': 'SirinVPN.AppImage' if kind == 'appimage' else 'SirinVPN-setup.exe'}}
        outcomes('app-updates', 'install-' + kind, verified + [check('I confirm installation'), click('Install authenticated update')], 'installReleaseUpdate', state)
    outcomes('app-updates', 'bind-installed-baseline', verified + [check('I confirm verification'), click('Verify installed release')], 'installReleaseUpdate', {'releaseCandidate': {'baseline_bind_available': True, 'baseline_bound': False}})
    outcomes('app-updates', 'restore-retained-appimage', app + [check('Restore AppImage'), click('Restore previous AppImage')], 'rollbackReleaseUpdate', {'releaseConfigured': True, 'releaseCandidate': {'installer_kind': 'appimage'}})
    local = general + [click('Review local component')]
    for name, state in [('loading', {'holds': ['localComponentUpdateStatus']}), ('check-failed', {'errors': {'localComponentUpdateStatus': ERROR}}), ('installer-unavailable', {'responses': {'localComponentUpdateStatus': {'install_available': False, 'update_required': True}}})]:
        case('app-updates', 'local-component-' + name, local, state)
