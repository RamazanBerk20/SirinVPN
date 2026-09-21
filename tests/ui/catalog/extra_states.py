"""Additional conditional controls, maintenance prerequisites and validation states."""
from scenarios import *
from workflows import check, PASS, SOURCE, KEY

def extra_states(p, add):
    d = True
    general = settings('desktop', 'general')
    connection = settings('desktop', 'connection')
    network = settings('desktop', 'network')
    recovery = settings('desktop', 'recovery')
    maintenance = settings('desktop', 'maintenance')

    def outcomes(family, name, base, last, method, state=None):
        for kind, err in [('in-progress', {'holds': [method]}), ('failed', {'errors': {method: ERROR}}), ('completed', {})]:
            case = add(family, name + '-' + kind, base + ([{'patch': err}] if err else []) + [last], state, True)
            case['required_calls'] = [method]
    for result in ['pending', 'icmp_unavailable', 'no_usable_mtu', 'apply_failed']:
        add('measurements', 'mtu-' + result.replace('_', '-'), connection, {'local': {'mtu': {'outcome': result, 'suggested': None}}}, True)
    for result in ['pending', 'waiting_for_idle', 'comparing', 'selected', 'icmp_unavailable', 'protection_required']:
        add('measurements', 'transport-' + result.replace('_', '-'), [], {'local': {'transport_quality': {'selection': result}}}, True)
    for result in ['armed', 'blocking', 'failed', 'unknown']:
        add('protection', 'kill-switch-' + result, [], {'local': {'kill_switch_enabled': True, 'kill_switch_state': result}}, True)
    add('protection', 'recovery-waiting-for-user', [], {'local': {'state': 'degraded', 'waiting_for_user': True, 'kill_switch_enabled': True, 'kill_switch_state': 'blocking'}}, True)
    add('protection', 'startup-connection-active', connection, {'local': {'startup_service_enabled': True, 'connect_on_startup': True}, 'preferences': {'policy': {'connect_on_startup': True}}}, True)
    ports = network
    for kind, state in [('unsupported-vps', {'configuration': {'port_forwarding_enabled': False}}), ('no-authorized-devices', {'members': {'members': []}}), ('existing-port-forward', {'members': {'port_forwards': [{'protocol': 'tcp', 'public_port': 48080, 'device_id': DID, 'device_port': 8080}]}})]:
        add('port-forwarding', kind, ports, state, True)
    for public, device, name in [('48080', '8080', 'valid-tcp-rule'), ('53', '8080', 'reserved-public-port'), ('70000', '8080', 'public-port-out-of-range'), ('48080', '0', 'invalid-target-port')]:
        add('port-forwarding', name, ports + [fill('Public port', public), fill('Device port', device)], expand=True)
    add('port-forwarding', 'valid-udp-rule', ports + [fill('Protocol', 'udp'), fill('Public port', '48443'), fill('Device port', '443')], expand=True)
    forward = ports + [fill('Public port', '48080'), fill('Device port', '8080')]
    outcomes('port-forwarding', 'create-port-forward', forward, click('Open port'), 'createPortForward')
    member = [click('Devices'), click('Family', False), click('Access policy')]
    policy = {'emptyMember': True}
    for label in ['Invite ordinary members', 'Add devices to their own membership', 'Manage peer access for their devices', 'Manage public port forwarding to their devices']:
        add('member-policy', label.lower().replace(' ', '-'), member + [check(label)], policy, True)
    for value, name in [('Mon 09:00-17:00\nTue 18:00-24:00', 'weekly-access-windows'), ('not a time range', 'invalid-weekly-access')]:
        add('member-policy', name, member + [click('Edit UTC text'), fill('Weekly access (UTC)', value)], policy, True)
    add('member-policy', 'device-limit-and-expiration', member + [fill('Device limit', '3'), fill('Access expires (UTC)', '2026-12-31T23:59')], policy, True)
    outcomes('member-policy', 'save-member-policy', member + [fill('Device limit', '3')], click('Save access policy'), 'updateMemberPolicy', policy)
    for msg, name in [('This invitation has expired. Ask for a new code.', 'expired-code'), ('The invitation signature is invalid.', 'invalid-signature'), ('The invitation has no joins remaining.', 'invitation-used-up')]:
        add('join', name, [click('Invitation'), fill('Invitation code', 'sirin1.EXAMPLE'), click('Review invitation')], {'empty': True, 'errors': {'previewInvitation': msg}}, True)
    importbase = [click('Backup'), click('Choose file'), fill('Backup password', PASS), click('Restore backup')]
    for msg, name in [('The backup password is incorrect or the file is damaged.', 'wrong-backup-password'), ('A profile for this server already exists. Existing identities are never overwritten.', 'duplicate-backup-identity'), ('The backup format is newer than this app supports.', 'unsupported-backup-version')]:
        add('device-backups', name, importbase, {'empty': True, 'errors': {'importServerBackup': msg}}, True)
    app = general + [click('App updates')]
    verified = app + [fill('Release source', SOURCE), click('Check and verify release')]
    add('app-updates', 'preview-channel-review', app + [click('Preview')], expand=True)
    add('app-updates', 'release-already-current', verified, {'releaseCandidate': {'newer_than_running': False, 'release_version': '1.0.1'}}, True)
    add('app-updates', 'first-release-baseline-binding', verified, {'connected': False, 'releaseCandidate': {'baseline_bind_available': True, 'baseline_bound': False}}, True)
    install = verified + [check('I confirm installation')]
    outcomes('app-updates', 'install-authenticated-app-release', install, click('Install authenticated update'), 'installReleaseUpdate', {'connected': False})
    add('app-updates', 'retained-appimage-rollback', app, {'releaseCandidate': {'installer_kind': 'appimage'}, 'releaseConfigured': True}, True)
    local = general + [click('Review local component')]
    add('app-updates', 'local-component-upgrade-review', local, {'connected': False, 'componentUpdate': True}, True)
    outcomes('app-updates', 'update-local-vpn-component', local, click('Update local VPN component'), 'installLocalVpnComponent', {'connected': False, 'componentUpdate': True})
    new = [fill('IP address or hostname', 'vpn.example.com'), click('SSH agent'), click('Verify VPS')]
    inspected = new + [click('Fingerprint matches — inspect network')]
    add('provisioning', 'verified-new-vps-network', inspected, {'empty': True}, True)
    outcomes('provisioning', 'install-new-vps', inspected, click('Install SirinVPN'), 'provisionServer', {'empty': True})
    add('provisioning', 'network-port-conflict', inspected, {'empty': True, 'responses': {'inspectServerNetwork': {'public_endpoint': 'vpn.example.com', 'endpoint_addresses': ['192.0.2.12'], 'exposure': 'public_interface', 'assigned_addresses': [], 'required_ports': [{'protocol': 'udp', 'port': 51820}], 'issues': [{'code': 'port_conflict', 'blocking': True, 'message': 'UDP port 51820 is already owned by another service. Choose another port before installing.'}]}}}, True)
    uninstall = maintenance + [click('Remove saved server or uninstall SirinVPN', False), click('Uninstall from VPS', False), click('SSH agent'), click('Review uninstall')]
    add('removal', 'uninstall-fingerprint-review', uninstall, {'connected': False}, True)
    outcomes('removal', 'uninstall-vps', uninstall + [check('I verified this VPS fingerprint')], click('Uninstall SirinVPN'), 'uninstallServer', {'connected': False})
