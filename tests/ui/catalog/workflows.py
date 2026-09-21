"""Wizard stages, review dialogs, operation results and recovery workflows."""
from scenarios import click, fill, css, settings, mutate, patch, ID, MID, DID, CODE, ERROR
from copy import deepcopy
KEY = 'sirr1.' + 'RECOVERY-EXAMPLE-' * 45
PASS = 'Screenshot-example-2026'
SOURCE = 'https://updates.example.com/sirinvpn/'

def check(label):
    return {'label': label, 'check': True}

def workflows(p, add):
    d = True

    def outcome(family, name, actions, method, state=None, expand=True):
        for kind in ['in-progress', 'failed', 'completed']:
            opts = deepcopy(state or {})
            steps = deepcopy(actions)
            if kind == 'in-progress':
                steps.insert(len(steps) - 1, patch(holds=[method]))
            if kind == 'failed':
                steps.insert(len(steps) - 1, patch(errors={method: ERROR}))
            case = add(family, name + '-' + kind, steps, opts, expand)
            case['required_calls'] = [method]
    general = settings('desktop', 'general')
    connection = settings('desktop', 'connection')
    network = settings('desktop', 'network')
    recovery = settings('desktop', 'recovery')
    maintenance = settings('desktop', 'maintenance')
    devices = [click('Devices')]
    servers = [click('Servers')]
    add('servers', 'saved-server-list', servers, expand=True)
    add('servers', 'saved-server-list-disconnected', servers, {'connected': False}, True)
    add('servers', 'server-actions-menu', servers + [click('Actions for ' + 'My private VPS')], expand=True)
    for count in [4, 12]:
        add('servers', str(count) + '-saved-servers', servers, {'profileCount': count}, True)
    add('servers', 'long-server-names', servers, {'profileCount': 4, 'longNames': True}, True)
    add('servers', 'server-rename-confirmation', servers + [click('Actions for My private VPS'), click('Rename locally')], expand=True)
    for label in ['Rename device', 'Suspend member', 'Revoke all member devices', 'Enable mutual device access', 'Revoke Android phone', 'Make Admin', 'Transfer ownership']:
        action = devices + [click('Actions for Android phone'), click(label)]
        add('member-actions', label.lower().replace(' ', '-') + '-confirmation', action, expand=True)
        method = {'Rename device': 'renameDevice', 'Suspend member': 'updateMemberSuspension', 'Revoke all member devices': 'revokeMemberDevices', 'Enable mutual device access': 'updateDevicePeerCommunication', 'Revoke Android phone': 'revokeDevice', 'Make Admin': 'updateMemberAccess', 'Transfer ownership': 'transferOwnership'}[label]
        add('member-actions', label.lower().replace(' ', '-') + '-failed', action, {'errors': {method: ERROR}}, True)
    expandmember = devices + [click('Family', False)]
    add('member-policy', 'member-policy-editor', expandmember + [click('Access policy')], {'emptyMember': True}, True)
    for name, st in [('member-suspended', {'suspendedMember': True}), ('active-single-use-invitation', {'activeInvitation': 'single'}), ('active-reusable-invitation', {'activeInvitation': 'reusable'}), ('existing-member-device-invitation', {'activeInvitation': 'device'}), ('delegated-member-permissions', {'role': 'member', 'delegated': True}), ('weekly-member-access-limits', {'limitedMember': True})]:
        add('devices', name, devices, st, True)
    add('invitations', 'delegated-member-invitation', devices + [click('Invite member')], {'role': 'member', 'delegated': True}, True)
    add('invitations', 'invitation-capabilities-loading', devices + [click('Invite member')], {'holds': ['serverConfiguration']}, True)
    add('invitations', 'invitation-capabilities-unavailable', devices + [click('Invite member')], {'errors': {'serverConfiguration': ERROR}}, True)
    rk = recovery
    for name, opts in [('recovery-loading', {'holds': ['recoverySettings']}), ('recovery-failed', {'errors': {'recoverySettings': ERROR}}), ('recovery-key-registered', {'recoverySettings': {'key': {'recovery_id': 'example-recovery-key', 'identity_fingerprint': 'SHA256:' + 'A' * 43}}}), ('recovery-enrollment-finishing', {'recoverySettings': {'enrollment_finishing': True}}), ('recovery-issuance-unavailable', {'recoverySettings': {'can_issue_key': False}}), ('recovery-unsupported-vps', {'configuration': {'recovery_keys_enabled': False}})]:
        add('recovery-keys', name, rk, opts, True)
    create = rk + [check('I understand that anyone holding this key'), click('Create recovery key')]
    outcome('recovery-keys', 'create-offline-recovery-key', create, 'createRecoveryKey')
    outcome('recovery-keys', 'export-recovery-package', create + [fill('Recovery package password', PASS), fill('Repeat package password', PASS), click('Save encrypted recovery package')], 'exportRecoveryPackage')
    outcome('recovery-keys', 'save-administrator-recovery-policy', rk + [click('Administrator recovery policy'), check('Morgan'), click('Save recovery policy')], 'updateRecoveryPolicy')
    add('recovery-keys', 'revoke-registered-recovery-key', rk + [click('Revoke recovery key')], {'recoverySettings': {'key': {'recovery_id': 'example-recovery-key', 'identity_fingerprint': 'SHA256:' + 'A' * 43}}}, True)
    diag = maintenance + [click('Run diagnostics')]
    outcome('diagnostics', 'run-diagnostics', diag, 'diagnostics')
    for report in ['all-pass', 'failures', 'warnings-only', 'empty']:
        add('diagnostics', 'diagnostic-report-' + report, diag, {'diagnosticPreset': report}, True)
    wifi = general
    for name, st in [('trusted-wifi', {'current_network': 'trusted_wifi', 'can_trust_current': True, 'trusted_networks': [{'id': 'home-network', 'label': 'Home Wi-Fi'}, {'id': 'office-network', 'label': 'Office'}]}), ('other-network', {'current_network': 'other_network', 'can_trust_current': False}), ('wifi-unavailable', {'current_network': 'unavailable', 'can_trust_current': False}), ('recognition-allowed', {'recognition_permission': True, 'can_trust_current': True, 'current_network_token': 'example-network'}), ('automation-armed', {'state': 'armed', 'automation_status': 'waiting_for_wifi', 'profile_id': ID, 'policy': {'enabled': True, 'server_id': ID}}), ('automation-paused', {'state': 'armed', 'profile_id': ID, 'policy': {'enabled': True, 'server_id': ID}, 'automation_status': 'waiting_for_network_change', 'paused_on_current_network': True}), ('recognition-unsupported', {'recognition_supported': False})]:
        if name == 'trusted-wifi':
            st.update(current_network_token='home-network', network_names={'home-network': 'Home hotspot', 'office-network': 'Office hotspot'})
        if name in ['other-network', 'wifi-unavailable']:
            st.update(current_network_token=None, network_names={})
        add('wifi', name, wifi, {'wifi': st}, True)
    outcome('wifi', 'refresh-network', wifi + [click('Refresh network')], 'getWifiPolicy')
    empty = {'empty': True}
    join = [click('Invitation'), fill('Invitation code', CODE)]
    add('join', 'invitation-code-entered', join, empty, True)
    outcome('join', 'review-invitation', join + [click('Review invitation')], 'previewInvitation', empty)
    review = join + [click('Review invitation')]
    for name, preview in [('older-invitation-names', {'recipient_names': False}), ('existing-member-device', {'creates_member': False}), ('admin-invitation', {'access_level': 'admin'}), ('owner-device-invitation', {'access_level': 'owner', 'creates_member': False})]:
        add('join', name, review, {**empty, 'invitationPreview': preview}, True)
    ready = review + [fill('Your device name', 'My laptop')]
    add('join', 'recipient-names-entered', ready, empty, True)
    outcome('join', 'join-reviewed-invitation', ready + [click('Join server')], 'joinServer', empty)
    backup = [click('Backup'), click('Choose file'), fill('Backup password', PASS)]
    add('device-backups', 'device-import-ready', backup, empty, True)
    outcome('device-backups', 'device-import', backup + [click('Restore backup')], 'importServerBackup', empty)
    owner = [click('Recovery key')] + [fill('Recovery key', KEY), click('Review recovery key')]
    outcome('owner-recovery', 'review-offline-owner-key', owner, 'previewRecoveryKey', empty)
    replace = {'responses': {'previewRecoveryKey': {'existing_profile': True, 'preview': {'server_id': ID, 'server_name': 'My private VPS', 'host': 'vpn.example.com', 'recovery_id': 'example-recovery-key', 'server_identity_fingerprint': 'SHA256:' + 'A' * 43}}}}
    add('owner-recovery', 'replace-existing-owner-profile-review', owner, {**empty, **replace}, True)
    ownerready = owner + [fill('New Owner device name', 'Recovered laptop'), check('Revoke all old Owner device')]
    outcome('owner-recovery', 'recover-owner-access', ownerready + [click('Recover Owner access')], 'recoverOwnerAccess', empty)
    export = recovery + [click('Export device backup', False)]
    filled = export + [click('Choose file'), fill('Password', PASS), fill('Repeat password', PASS), check('I understand this export')]
    add('device-backups', 'device-export-ready', filled, expand=True)
    add('device-backups', 'device-export-password-mismatch', export + [click('Choose file'), fill('Password', PASS), fill('Repeat password', 'different-password')], expand=True)
    outcome('device-backups', 'device-export', filled + [click('Create encrypted backup')], 'exportServerBackup')
    rotation = recovery + [click('Rotate device keys', False), check('I understand the tunnel')]
    outcome('key-rotation', 'rotate-desktop-device-keys', rotation + [click('Rotate both keys')], 'rotateDeviceKeys')
    add('key-rotation', 'resume-interrupted-key-rotation', recovery + [click('Resume key rotation', False)], {'pendingRotation': True}, True)
    endpoint = maintenance + [click('Move devices to a new VPS address', False)]
    add('endpoint', 'share-migration-introduction', endpoint + [click('Share migration')], expand=True)
    retrieve = endpoint + [click('Share migration'), click('Retrieve signed update')]
    outcome('endpoint', 'retrieve-signed-address-update', retrieve, 'createEndpointUpdate')
    outcome('endpoint', 'publish-signed-address-update', retrieve + [click('Publish on old VPS')], 'publishEndpointUpdate')
    outcome('endpoint', 'apply-signed-address-update', endpoint + [fill('Signed endpoint update', 'sire1.' + 'EXAMPLE-' * 60), click('Verify and switch')], 'applyEndpointUpdate')
    remove = maintenance + [click('Remove saved server or uninstall SirinVPN', False)]
    outcome('removal', 'remove-local-server', remove + [click('Remove from this device', False)], 'removeServer', {'connected': False})
    add('removal', 'uninstall-vps-ssh-details', remove + [click('Uninstall from VPS', False)], {'connected': False}, True)
    setup = [fill('IP address or hostname', 'vpn.example.com'), click('SSH agent')]
    add('provisioning', 'new-vps-details-ready', setup, empty, True)
    outcome('provisioning', 'probe-new-vps', setup + [click('Verify VPS')], 'probeHostKey', empty)
    for method in ['Private key', 'Password', 'SSH agent']:
        add('provisioning', 'new-vps-auth-' + method.lower().replace(' ', '-'), [click(method)], empty, True)
    operations = [('vps-backup', 'Back up VPS', recovery, 'Create VPS backup', 'exportVpsBackup', [click('Choose file'), fill('Backup password', PASS), fill('Repeat password', PASS)]), ('vps-restore', 'Restore or migrate VPS', recovery, 'Restore VPS', 'restoreVpsBackup', [click('Choose file'), fill('Backup password', PASS)]), ('vps-repair', 'Repair VPS configuration', maintenance, 'Repair VPS', 'repairServer', []), ('vps-updates', 'Update VPS software', maintenance, 'Continue', 'manageVpsRelease', [])]
    for family, label, base, submit, method, fields in operations:
        base = base + [click(label, False), click('Continue to VPS setup')]
        for authentication in ['Password', 'SSH agent']:
            add(family, family + '-ssh-' + authentication.lower().replace(' ', '-'), base + [click(authentication)], {'connected': False}, True)
        add(family, family + '-sudo-login', base + [fill('SSH username', 'admin')], {'connected': False}, True)
        add(family, family + '-saved-ssh-login', base, {'connected': False, 'savedLogin': {'username': 'admin', 'ssh_port': 2222, 'authentication': 'agent', 'private_key_path': None}}, True)
        add(family, family + '-ssh-wallet-error', base, {'connected': False, 'errors': {'getSshLogin': 'The desktop wallet is locked. Unlock it and try again.'}}, True)
        inspect = base + fields + [click('SSH agent'), click(submit)]
        add(family, family + '-verify-new-ssh-fingerprint', inspect, {'connected': False}, True)
        add(family, family + '-ssh-fingerprint-changed', inspect, {'connected': False, 'sshInspection': {'status': 'changed'}}, True)
        add(family, family + '-ssh-fingerprint-checking', inspect, {'connected': False, 'holds': ['inspectSshHost']}, True)
        add(family, family + '-ssh-fingerprint-failed', inspect, {'connected': False, 'errors': {'inspectSshHost': ERROR}}, True)
        if family != 'vps-updates':
            outcome(family, family + '-operation', inspect, 'repairServer' if family == 'vps-repair' else method, {'connected': False, 'sshInspection': {'status': 'trusted'}})
        else:
            release = inspect
            trusted = {'connected': False, 'sshInspection': {'status': 'trusted'}}
            add(family, 'update-setup-choose-source', release, trusted, True)
            for source, name in [('http://updates.example.com/', 'http-source-rejected'), ('https://updates.example.com/releases', 'missing-trailing-slash'), (SOURCE, 'valid-https-source')]:
                add(family, 'update-setup-' + name, release + [fill('Release source', source)], trusted, True)
            verified = release + [fill('Release source', SOURCE), click('Verify release')]
            add(family, 'first-release-verified', verified, trusted, True)
            outcome(family, 'verify-first-release', verified, 'manageVpsRelease', trusted)
            outcome(family, 'finish-update-setup', verified + [click('Finish setup')], 'manageVpsRelease', trusted)
            configured = {**trusted, 'releaseConfigured': True, 'releaseSource': SOURCE}
            for name, opts in [('installed-release-and-schedule', {}), ('interrupted-update-recovery', {'releasePending': True}), ('installed-receipt-mismatch', {'releaseMatches': False}), ('automatic-security-updates-enabled', {'releaseAutomatic': True})]:
                add(family, name, release, {**configured, **opts}, True)
            add(family, 'verified-vps-update-available', release + [click('Check for updates')], configured, True)
            outcome(family, 'install-reviewed-vps-update', release + [click('Check for updates'), click('Install update 1.0.2')], 'manageVpsRelease', configured)
            outcome(family, 'save-automatic-update-schedule', release + [check('Automatic security updates'), click('Save schedule')], 'manageVpsRelease', configured)
            add(family, 'rollback-vps-review', release + [click('Restore previous version 1.0.0'), check('Restore version 1.0.0')], configured, True)
    dns_setup = network + [click('Configure VPS DNS'), click('Continue to VPS setup')]
    for mode in ['Recursive', 'DNS over TLS', 'DNS over HTTPS']:
        add('dns', 'desktop-dns-' + mode.lower().replace(' ', '-'), dns_setup + [click(mode)], {'connected': False}, True)
    add('dns', 'desktop-private-dns-records', dns_setup + [click('Replace')], {'connected': False}, True)
    app = general + [click('App updates')]
    for source, name in [('http://updates.example.com/', 'invalid-http-source'), (SOURCE, 'valid-source')]:
        add('app-updates', 'desktop-' + name, app + [fill('Release source', source)], expand=True)
    appcheck = app + [fill('Release source', SOURCE), click('Check and verify release')]
    outcome('app-updates', 'desktop-verify-app-release', appcheck, 'checkReleaseUpdate')
    for kind in ['appimage', 'windows', 'unsupported']:
        add('app-updates', 'installer-kind-' + kind, appcheck, {'releaseCandidate': {'installer_kind': kind, 'debian_install_available': False, 'appimage_install_available': kind == 'appimage', 'windows_install_available': kind == 'windows'}}, True)
