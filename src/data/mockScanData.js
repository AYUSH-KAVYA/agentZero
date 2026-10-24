/**
 * Realistic macOS Sonoma / Sequoia Security Audit Mock Data
 * Allows full visualization and interactive testing of the UI,
 * vulnerability maps, CIS Apple benchmarks, and network topology on macOS / dev mode.
 */

export const mockScanData = {
  timestamp: new Date().toISOString(),
  scan_type: 'full',
  posture: {
    score: 72.4,
    grade: 'C',
    status: 'Needs Hardening',
    penalties: {
      critical: 0.0,
      high: 16.0,
      medium: 8.0,
      low: 3.6,
    },
  },
  system: {
    scan_type: 'system',
    timestamp: new Date().toISOString(),
    summary: {
      total_modules: 26,
      completed: 26,
      errors: 0,
      status_counts: { pass: 18, warn: 5, fail: 3, info: 0, error: 0 },
      findings_by_severity: { critical: 0, high: 2, medium: 4, low: 3, info: 5 },
    },
    modules: {
      os_info: {
        category: 'macOS System Information',
        status: 'pass',
        data: {
          productname: 'macOS',
          productversion: '14.5',
          buildversion: '23F79',
          platform: 'macOS-14.5-arm64-arm-64bit',
          architecture: 'arm64',
          kernel_version: '23.5.0',
          node_name: 'MacBook-Pro-SecOps.local',
          hardware_model: 'Mac15,6',
          processor: 'Apple M3 Pro',
          uptime_raw: '12 days, 4 hours, 2 users',
        },
        findings: [],
      },
      dotnet_versions: {
        category: 'FileVault 2 Disk Encryption',
        status: 'pass',
        data: {
          filevault_enabled: true,
          raw: 'FileVault is On.',
        },
        findings: [],
      },
      amsi_providers: {
        category: 'System Integrity Protection (SIP)',
        status: 'pass',
        data: {
          sip_enabled: true,
          raw: 'System Integrity Protection status: enabled.',
        },
        findings: [],
      },
      defender: {
        category: 'Gatekeeper & XProtect',
        status: 'pass',
        data: {
          gatekeeper_enabled: true,
          xprotect_present: true,
          raw: 'assessments enabled',
        },
        findings: [],
      },
      firewall: {
        category: 'Application Firewall',
        status: 'fail',
        data: {
          firewall_enabled: false,
          stealth_mode: false,
          block_all: false,
        },
        findings: [
          {
            severity: 'high',
            title: 'macOS Application Firewall is Disabled',
            description: 'The built-in application firewall is switched off, leaving listening services directly exposed to the local network.',
            remediation: 'Enable the firewall in System Settings > Network > Firewall or run "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on".',
          },
          {
            severity: 'low',
            title: 'Firewall Stealth Mode is Disabled',
            description: 'Stealth mode prevents the Mac from responding to ICMP ping and port probes from unauthorized hosts.',
            remediation: 'Enable stealth mode via "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on".',
          },
        ],
      },
      secure_boot: {
        category: 'Apple Silicon Secure Boot Policy',
        status: 'pass',
        data: {
          arch: 'arm64',
          boot_args: '',
          secure_boot_enforced: true,
          bputil_status: 'Full Security Mode Enforced',
        },
        findings: [],
      },
      autorun: {
        category: 'LaunchDaemons Persistence',
        status: 'pass',
        data: {
          count: 3,
          daemons: [
            { name: 'com.apple.installer.cleanup.plist', path: '/Library/LaunchDaemons/com.apple.installer.cleanup.plist' },
            { name: 'com.crowdstrike.falcon.plist', path: '/Library/LaunchDaemons/com.crowdstrike.falcon.plist' },
            { name: 'com.jamf.management.daemon.plist', path: '/Library/LaunchDaemons/com.jamf.management.daemon.plist' },
          ],
        },
        findings: [],
      },
      sysmon: {
        category: 'LaunchAgents Persistence',
        status: 'pass',
        data: {
          count: 2,
          agents: [
            { name: 'com.google.keystone.agent.plist', location: '~/Library/LaunchAgents' },
            { name: 'sh.brew.postgresql.plist', location: '~/Library/LaunchAgents' },
          ],
        },
        findings: [],
      },
      uac_policies: {
        category: 'Root Account & Sudoers Policy',
        status: 'pass',
        data: {
          root_enabled: false,
          nopasswd_rules: [],
          sudoers_status: 'Protected by root permissions (secure)',
        },
        findings: [],
      },
      local_users: {
        category: 'Directory Users & Guest Account',
        status: 'warn',
        data: {
          users: ['admin', 'analyst', 'Guest'],
          guest_enabled: true,
        },
        findings: [
          {
            severity: 'medium',
            title: 'Guest Account is Enabled',
            description: 'The macOS Guest account allows anonymous users to log into the system with guest sessions.',
            remediation: 'Disable the Guest account in System Settings > Users & Groups > Guest User.',
          },
        ],
      },
      local_groups: {
        category: 'Admin & Wheel Groups',
        status: 'pass',
        data: {
          admin_members: ['root', 'admin', 'analyst'],
          wheel_members: ['root'],
        },
        findings: [],
      },
      ms_updates: {
        category: 'Software Update Configuration',
        status: 'pass',
        data: {
          automatic_check: true,
          schedule_status: 'Automatic check is on',
        },
        findings: [],
      },
      hotfixes: {
        category: 'Rapid Security Responses (RSR)',
        status: 'pass',
        data: {
          build_version: '23F79',
          extra_version: '(a)',
        },
        findings: [],
      },
      rdp_settings: {
        category: 'Remote Login (SSH) Policy',
        status: 'warn',
        data: {
          remote_login_enabled: true,
        },
        findings: [
          {
            severity: 'medium',
            title: 'Remote Login (OpenSSH) is Enabled',
            description: 'SSH access is enabled on the system. If SSH is not required for administration, it should be disabled to prevent network brute-force attacks.',
            remediation: 'Turn off Remote Login in System Settings > General > Sharing, or run "sudo systemsetup -setremotelogin off".',
          },
        ],
      },
      rdp_sessions: {
        category: 'Screen Sharing & Remote Management',
        status: 'pass',
        data: {
          screen_sharing_active: false,
        },
        findings: [],
      },
      rdp_connections: {
        category: 'Sharing Services & Remote Apple Events',
        status: 'pass',
        data: {
          remote_apple_events: false,
        },
        findings: [],
      },
      ntlm_settings: {
        category: 'Account & Password Policies',
        status: 'warn',
        data: {
          policy_enforced: false,
          raw: 'No global password length restrictions set',
        },
        findings: [
          {
            severity: 'medium',
            title: 'No Password Complexity Policy Configured',
            description: 'No global minimum password length or complexity rules are enforced via pwpolicy, allowing weak passwords.',
            remediation: 'Deploy a configuration profile or enforce pwpolicy rules with minimum 14 characters.',
          },
        ],
      },
      antivirus: {
        category: 'EDR & System Extensions',
        status: 'pass',
        data: {
          count: 1,
          extensions: ['com.crowdstrike.falcon.Agent (Falcon Endpoint Security)'],
        },
        findings: [],
      },
      certificates: {
        category: 'Keychain Root Certificates',
        status: 'pass',
        data: {
          system_keychain_certs: 174,
          custom_root_count: 0,
        },
        findings: [],
      },
      installed_products: {
        category: 'Applications & Homebrew',
        status: 'info',
        data: {
          applications: ['Visual Studio Code.app', 'Google Chrome.app', 'Slack.app', 'Docker.app', 'AgentZero.app'],
          brew_packages: ['python@3.11 3.11.9', 'node 20.14.0', 'nmap 7.94', 'openssl@3 3.3.1'],
        },
        findings: [],
      },
      audit_policy: {
        category: 'Audit Policy Settings',
        status: 'pass',
        data: {
          audit_control_present: true,
          flags: 'flags:lo,aa,ad,fd',
        },
        findings: [],
      },
      powershell_history: {
        category: 'Shell History & Exposed Secrets',
        status: 'pass',
        data: {
          history_files_checked: ['/Users/analyst/.zsh_history'],
          matches_count: 0,
        },
        findings: [],
      },
      environment: {
        category: 'Environment & PATH',
        status: 'pass',
        data: {
          path_entries: ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'],
          insecure_entries: [],
        },
        findings: [],
      },
      file_info: {
        category: 'SUID Binaries & File Permissions',
        status: 'pass',
        data: {
          count: 7,
          suid_binaries: ['/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/crontab', '/usr/bin/login', '/usr/bin/top', '/usr/sbin/traceroute'],
        },
        findings: [],
      },
      file_listing: {
        category: 'User Credential & Key Files',
        status: 'pass',
        data: {
          sensitive_files_found: ['/Users/analyst/.ssh/id_ed25519'],
        },
        findings: [],
      },
      group_policy: {
        category: 'Configuration Profiles & MDM',
        status: 'info',
        data: {
          enrolled: true,
          enrollment_status: 'Enrolled via Apple Automated Device Enrollment (Jamf Pro)',
        },
        findings: [],
      },
    },
  },
  network: {
    scan_type: 'network',
    timestamp: new Date().toISOString(),
    summary: {
      total_modules: 10,
      completed: 10,
      live_hosts: 5,
      open_ports: 4,
      network_shares: 1,
    },
    modules: {
      interfaces: {
        category: 'System Interface Connectors',
        data: [
          { Name: 'en0 (Wi-Fi)', Status: 'Up', IPv4Address: '10.254.207.3', MacAddress: '3c:22:fb:4a:18:22', LinkSpeed: '866 Mbps' },
          { Name: 'lo0 (Loopback)', Status: 'Up', IPv4Address: '127.0.0.1', MacAddress: '00:00:00:00:00:00', LinkSpeed: '10 Gbps' },
        ],
        findings: [],
      },
      arp_table: {
        category: 'ARP Table & Network Neighbors',
        data: [
          { ip: '10.254.200.1', mac: '4c:f4:1c:4c:d8:25', type: 'Static', raw: 'gateway.internal (10.254.200.1)' },
          { ip: '10.254.200.45', mac: '00:11:32:9f:aa:12', type: 'Dynamic', raw: 'nas.internal (10.254.200.45)' },
          { ip: '10.254.200.58', mac: '12:ce:d7:8e:e3:7a', type: 'Dynamic', raw: 'client.internal (10.254.200.58)' },
        ],
        findings: [],
      },
      dns_cache: {
        category: 'DNS Resolvers & Configuration',
        data: [
          { resolver: 'resolver #1', nameservers: ['1.1.1.1', '8.8.8.8'], domain: 'internal.corp' },
        ],
        findings: [],
      },
      network_profiles: {
        category: 'macOS Network Services',
        data: [
          { name: 'Wi-Fi', status: 'configured' },
          { name: 'Thunderbolt Bridge', status: 'configured' },
          { name: 'Active Wi-Fi SSID', ssid: 'Corp_SecOps_5G' },
        ],
        findings: [],
      },
      network_shares: {
        category: 'Mounted & Shared File Systems',
        data: [],
        findings: [],
      },
      connections: {
        category: 'Active Network Connections',
        data: [
          { command: 'ssh', pid: '4120', user: 'analyst', connection: '10.254.207.3:51240->10.254.200.58:22', state: 'ESTABLISHED' },
          { command: 'Google Chrome', pid: '2810', user: 'analyst', connection: '10.254.207.3:51310->142.251.126.94:443', state: 'ESTABLISHED' },
        ],
        findings: [],
      },
      rpc_endpoints: {
        category: 'Bonjour & Network Services',
        data: [
          { command: 'mDNSResponder', pid: '142', user: '_mdnsresponder', protocol: 'mDNS / Bonjour (UDP 5353)' },
        ],
        findings: [],
      },
      open_ports: {
        category: 'Listening Ports & Services',
        data: [
          { command: 'sshd', pid: '1205', user: 'root', type: 'IPv4', address: '*:22', port: 22 },
          { command: 'postgres', pid: '1762', user: 'analyst', type: 'IPv4', address: '127.0.0.1:5432', port: 5432 },
          { command: 'rapportd', pid: '1451', user: 'analyst', type: 'IPv4', address: '*:49283', port: 49283 },
        ],
        findings: [
          {
            severity: 'medium',
            title: 'Sensitive Port 22 (SSH) Listening',
            description: 'Process "sshd" (PID 1205) is actively listening on port 22.',
            remediation: 'Verify whether SSH service is intended to accept incoming network connections.',
          },
        ],
      },
      lldp_cdp: {
        category: 'LLDP/CDP Infrastructure',
        data: [{ raw: 'Switch port bridge interface default gateway reachable via ARP 10.254.200.1' }],
        findings: [],
      },
      vlan_devices: {
        category: 'Attached VLAN Vectors',
        data: [
          { subnet: '10.254.200.0/22', broadcast: '10.254.203.255', active_hosts: 5 },
        ],
        findings: [],
      },
    },
    topology_nodes: [
      { id: 'host', label: 'Local macOS Host (MacBook)', ip: '10.254.207.3', type: 'target', status: 'warning', role: 'Audit Target', x: 400, y: 220 },
      { id: 'gw', label: 'Default Gateway Router', ip: '10.254.200.1', type: 'router', status: 'normal', role: 'Subnet Gateway', x: 150, y: 100 },
      { id: 'dc', label: 'DNS / Directory Node', ip: '1.1.1.1', type: 'server', status: 'normal', role: 'Cloudflare DNS :53', x: 650, y: 100 },
      { id: 'nas', label: 'Storage NAS', ip: '10.254.200.45', type: 'storage', status: 'normal', role: 'SMB/NFS Server', x: 650, y: 340 },
      { id: 'client', label: 'Local Network Peer', ip: '10.254.200.58', type: 'client', status: 'active', role: 'SSH Client :22', x: 150, y: 340 },
    ],
  },
  vulnerabilities: {
    total: 3,
    critical: 0,
    high: 2,
    medium: 1,
    low: 0,
    findings: [
      {
        cve_id: 'CVE-2023-41064',
        title: 'macOS ImageIO Buffer Overflow Vulnerability (BLASTPASS Zero-Click)',
        description: 'A buffer overflow flaw in ImageIO allows remote attackers to execute arbitrary code with kernel privileges via crafted image files.',
        cvss_score: 9.8,
        severity: 'critical',
        category: 'ImageIO / Remote Code Execution',
        exploit_available: true,
        exploit_type: 'Zero-Click RCE PoC',
        exploit_source: 'Citizen Lab / BLASTPASS Research',
        remediation: 'Update to macOS Sonoma 14.0 or apply macOS Ventura 13.5.2 / macOS Security Response immediately.',
      },
      {
        cve_id: 'CVE-2024-27842',
        title: 'Apple PackageKit Directory Traversal & SIP Bypass',
        description: 'A logic issue in PackageKit allowed an unprivileged application to bypass System Integrity Protection (SIP) restrictions via path traversal during package extraction.',
        cvss_score: 7.5,
        severity: 'high',
        category: 'SIP Bypass / Privilege Escalation',
        exploit_available: true,
        exploit_type: 'SIP Bypass PoC',
        exploit_source: 'Microsoft Threat Intelligence',
        remediation: 'Update macOS to version 14.5 or later.',
      },
      {
        cve_id: 'CVE-2024-27834',
        title: 'Apple CoreGraphics Type Confusion Arbitrary Code Execution',
        description: 'An issue was addressed in CoreGraphics where parsing a crafted document could lead to unexpected process termination or arbitrary code execution.',
        cvss_score: 7.8,
        severity: 'high',
        category: 'CoreGraphics Code Execution',
        exploit_available: false,
        remediation: 'Update to macOS Sonoma 14.5 or macOS Sequoia 15.0.',
      },
    ],
    cis_benchmark: {
      score: 76.9,
      total_rules: 13,
      passed: 10,
      failed: 3,
      warnings: 0,
      rule_evaluations: [
        {
          rule_id: 'CIS-1.1',
          title: "Ensure 'Check for Software Updates' is Enabled",
          category: 'Software Updates',
          severity: 'high',
          status: 'PASS',
          actual_value: true,
          expected_value: true,
          detail: 'Compliant: current value is True',
          description: 'Background software update checks ensure zero-day vulnerabilities and Rapid Security Responses are received promptly.',
          remediation: 'Enable automatic updates via "sudo softwareupdate --schedule on".',
        },
        {
          rule_id: 'CIS-2.1',
          title: 'Ensure FileVault 2 Full Disk Encryption is Enabled',
          category: 'Storage Security',
          severity: 'critical',
          status: 'PASS',
          actual_value: true,
          expected_value: true,
          detail: 'Compliant: FileVault is active and encrypting startup container',
          description: 'FileVault secures the APFS startup container by encrypting all user data and system caches at rest.',
          remediation: 'Enable FileVault in System Settings > Privacy & Security or run "sudo fdesetup enable".',
        },
        {
          rule_id: 'CIS-2.2',
          title: 'Ensure System Integrity Protection (SIP) is Enabled',
          category: 'System Integrity',
          severity: 'critical',
          status: 'PASS',
          actual_value: true,
          expected_value: true,
          detail: 'Compliant: csrutil status is enabled',
          description: 'System Integrity Protection locks critical directories (/System, /usr, /bin) and disallows unauthorized dtrace/kext loading.',
          remediation: 'Boot into Recovery Mode and run "csrutil enable" in Terminal.',
        },
        {
          rule_id: 'CIS-2.3',
          title: 'Ensure Gatekeeper Assessments are Enabled',
          category: 'Code Signing & Malware Protection',
          severity: 'critical',
          status: 'PASS',
          actual_value: true,
          expected_value: true,
          detail: 'Compliant: spctl assessments enabled',
          description: 'Gatekeeper validates Developer ID code signatures and Apple notarization before binary execution.',
          remediation: 'Enable Gatekeeper assessments via "sudo spctl --master-enable".',
        },
        {
          rule_id: 'CIS-2.4',
          title: 'Ensure macOS Application Firewall is Enabled',
          category: 'Network Security',
          severity: 'high',
          status: 'FAIL',
          actual_value: false,
          expected_value: true,
          detail: 'Non-compliant: Application firewall is disabled',
          description: 'The application firewall monitors and blocks incoming connections to non-whitelisted sockets and daemons.',
          remediation: 'Enable firewall via "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on".',
        },
      ],
    },
  },
};
