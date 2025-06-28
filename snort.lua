-- Snort 3 Basic Configuration File

HOME_NET = '192.168.146.97/24'  -- Replace with your actual VM IP range

ips = {
  enable_builtin_rules = true,
  include = '/etc/snort/rules/local.rules'
}

daq = {
  module = 'afpacket',
  interface = 'eth0',
  mode = 'passive'
}

decode = {}
search_engine = {}
stream = {}
reassembly = {}
file_id = {}

alert_fast = {
  file = true
}
