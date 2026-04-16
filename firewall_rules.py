# firewall_rules.py
# Each rule is a dictionary describing what traffic to block or allow.
# Fields set to None act as wildcards — they match anything.

FIREWALL_RULES = [
    {
        # Rule 1: Block ALL traffic from h1 (10.0.0.1) to h3 (10.0.0.3)
        # This demonstrates IP-based blocking
        'src_ip': '10.0.0.1',
        'dst_ip': '10.0.0.3',
        'proto':  None,         # None = match any protocol
        'port':   None,         # None = match any port
        'action': 'block'
    },
    {
        # Rule 2: Block HTTP traffic (TCP port 80) to h4
        # This demonstrates port-based blocking
        'src_ip': None,         # None = match any source
        'dst_ip': '10.0.0.4',
        'proto':  'tcp',
        'port':   80,
        'action': 'block'
    },
    # Default: everything else is allowed (handled by learning switch logic)
]