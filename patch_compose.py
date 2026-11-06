import yaml

with open('docker-compose.yml', 'r') as f:
    data = yaml.safe_load(f)

# Add networks
data['networks'] = {
    'public_net': {},
    'internal_net': {'internal': True}
}

# Assign services
if 'nginx' in data['services']:
    data['services']['nginx']['networks'] = ['public_net', 'internal_net']
if 'backend' in data['services']:
    data['services']['backend']['networks'] = ['internal_net']
if 'postgres' in data['services']:
    data['services']['postgres']['networks'] = ['internal_net']
if 'redis' in data['services']:
    data['services']['redis']['networks'] = ['internal_net']

with open('docker-compose.yml', 'w') as f:
    yaml.dump(data, f, sort_keys=False)

