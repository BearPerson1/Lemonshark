# Copyright(C) Facebook, Inc. and its affiliates.
from json import dump, load
from collections import OrderedDict
import random
from benchmark.utils import Print

class ConfigError(Exception):
    pass


class Key:
    def __init__(self, name, secret):
        self.name = name
        self.secret = secret

    @classmethod
    def from_file(cls, filename):
        assert isinstance(filename, str)
        with open(filename, 'r') as f:
            data = load(f)
        return cls(data['name'], data['secret'])


class Committee:
    ''' The committee looks as follows:
        "authorities: {
            "name": {
                "stake": 1,
                "primary: {
                    "primary_to_primary": x.x.x.x:x,
                    "worker_to_primary": x.x.x.x:x,
                },
                "workers": {
                    "0": {
                        "primary_to_worker": x.x.x.x:x,
                        "worker_to_worker": x.x.x.x:x,
                        "transactions": x.x.x.x:x
                    },
                    ...
                }
            },
            ...
        }
    '''

    def __init__(self, addresses, base_port):
        ''' The `addresses` field looks as follows:
            { 
                "name": ["host", "host", ...],
                ...
            }
        '''
        assert isinstance(addresses, OrderedDict)
        assert all(isinstance(x, str) for x in addresses.keys())
        assert all(
            isinstance(x, list) and len(x) > 1 for x in addresses.values()
        )
        assert all(
            isinstance(x, str) for y in addresses.values() for x in y
        )
        assert len({len(x) for x in addresses.values()}) == 1
        assert isinstance(base_port, int) and base_port > 1024

        self._cached_good_nodes = {}

        port = base_port
        self.json = {'authorities': OrderedDict()}
        for i, (name, hosts) in enumerate(addresses.items()): 
            host = hosts.pop(0)
            primary_addr = {
                'primary_to_primary': f'{host}:{port}',
                'worker_to_primary': f'{host}:{port + 1}',
                'primary_to_client': f'{host}:{port + 2}',
            }
            port += 3

            workers_addr = OrderedDict()
            for j, host in enumerate(hosts):
                workers_addr[j] = {
                    'primary_to_worker': f'{host}:{port}',
                    'transactions': f'{host}:{port + 1}',
                    'worker_to_worker': f'{host}:{port + 2}',
                }
                port += 3

            self.json['authorities'][name] = {
                'stake': 1,
                'primary': primary_addr,
                'workers': workers_addr,
                'primary_id': i + 1
            }
    
    def primary_to_client_addresses(self, faults=0):
        ''' Returns an ordered list of primary-to-client addresses. '''
        assert faults < self.size()
        addresses = []
        
        # Use the same cached random selection as primary_addresses
        good_nodes = self._get_good_nodes(faults)
        
        # Only include addresses for non-faulty nodes
        for name, authority in self.json['authorities'].items():
            if name in good_nodes:
                addresses += [authority['primary']['primary_to_client']]
    
        return addresses

    def _get_good_nodes(self, faults):
        """Helper method to ensure consistent random selection between calls"""
        if faults < 0:
            raise ValueError("Number of faults cannot be negative")
            
        if self.size() <= faults:
            raise ValueError(f"Number of faults ({faults}) must be less than committee size ({self.size()})")
            
        # Use cached selection if available for this fault count
        if faults in self._cached_good_nodes:
            return self._cached_good_nodes[faults]
        
        # Set a deterministic seed based on committee composition
        # This ensures same faulty nodes are selected for same committee
        committee_hash = hash(tuple(sorted(self.json['authorities'].keys())))
        random.seed(committee_hash)
        
        try:
            all_authorities = list(self.json['authorities'].items())
            if not all_authorities:
                raise ValueError("Committee cannot be empty")
                
            good_nodes = set(name for name, _ in random.sample(all_authorities, self.size() - faults))
            
            # Cache the selection
            self._cached_good_nodes[faults] = good_nodes
            
            if faults > 0:
                faulty_nodes = [name for name, _ in all_authorities if name not in good_nodes]
                Print.info(f"Selected faulty nodes: {faulty_nodes}")
                
            return good_nodes

        finally:
        # Reset the random seed to not affect other random operations
            random.seed() 

    def primary_addresses(self, faults=0):
        ''' Returns an ordered list of primaries' addresses. '''
        assert faults < self.size()
        addresses = []
        
        # Use cached/consistent random selection
        good_nodes = self._get_good_nodes(faults)
        
        # Only include addresses for non-faulty nodes
        for name, authority in self.json['authorities'].items():
            if name in good_nodes:
                addresses += [authority['primary']['primary_to_primary']]
        
        return addresses

    def workers_addresses(self, faults=0):
        ''' Returns an ordered list of list of workers' addresses. '''
        assert faults < self.size()
        addresses = []
        
        # Use the same cached random selection as primary_addresses
        good_nodes = self._get_good_nodes(faults)
        
        # Only include workers for non-faulty nodes
        for name, authority in self.json['authorities'].items():
            if name in good_nodes:
                authority_addresses = []
                for id, worker in authority['workers'].items():
                    authority_addresses += [(id, worker['transactions'])]
                addresses.append(authority_addresses)
        
        return addresses

    def ips(self, name=None):
        ''' Returns all the ips associated with an authority (in any order). '''
        if name is None:
            names = list(self.json['authorities'].keys())
        else:
            names = [name]

        ips = set()
        for name in names:
            addresses = self.json['authorities'][name]['primary']
            ips.add(self.ip(addresses['primary_to_primary']))
            ips.add(self.ip(addresses['worker_to_primary']))
            ips.add(self.ip(addresses['primary_to_client']))

            for worker in self.json['authorities'][name]['workers'].values():
                ips.add(self.ip(worker['primary_to_worker']))
                ips.add(self.ip(worker['worker_to_worker']))
                ips.add(self.ip(worker['transactions']))

        return list(ips)

    def get_faulty_nodes(self, faults=0):
        ''' Returns the list of nodes selected as faulty '''
        assert faults < self.size()
        good_nodes = self._get_good_nodes(faults)
        return [name for name in self.json['authorities'].keys() if name not in good_nodes]

    def remove_nodes(self, nodes):
        ''' remove the `nodes` last nodes from the committee. '''
        assert nodes < self.size()
        self._cached_good_nodes = {}  # Clear cache when committee changes
        for _ in range(nodes):
            self.json['authorities'].popitem()

    def size(self):
        ''' Returns the number of authorities. '''
        return len(self.json['authorities'])

    def workers(self):
        ''' Returns the total number of workers (all authorities altogether). '''
        return sum(len(x['workers']) for x in self.json['authorities'].values())

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json, f, indent=4, sort_keys=True)

    @staticmethod
    def ip(address):
        assert isinstance(address, str)
        return address.split(':')[0]


class LocalCommittee(Committee):
    def __init__(self, names, port, workers):
        assert isinstance(names, list)
        assert all(isinstance(x, str) for x in names)
        assert isinstance(port, int)
        assert isinstance(workers, int) and workers > 0
        addresses = OrderedDict((x, ['127.0.0.1']*(1+workers)) for x in names)
        super().__init__(addresses, port)


class NodeParameters:
    def __init__(self, json):
        float_inputs = []
        inputs = []
        try:
            inputs += [json['header_size']]
            inputs += [json['max_header_delay']]
            inputs += [json['gc_depth']]
            inputs += [json['sync_retry_delay']]
            inputs += [json['sync_retry_nodes']]
            inputs += [json['batch_size']]
            inputs += [json['max_batch_delay']]
            if 'timeout' in json:
                inputs += [json['timeout']]

            if 'cross_shard_occurance_rate' in json:
                rate = float(json['cross_shard_occurance_rate'])
                if not 0.0 <= rate <= 1.0:
                    raise ConfigError('cross_shard_occurance_rate must be between 0.0 and 1.0')
                float_inputs.append(rate)

            if 'cross_shard_failure_rate' in json:
                rate = float(json['cross_shard_failure_rate'])
                if not 0.0 <= rate <= 1.0:
                    raise ConfigError('cross_shard_failure_rate must be between 0.0 and 1.0')
                float_inputs.append(rate)

            if 'causal_transactions_collision_rate' in json:
                rate = float(json['causal_transactions_collision_rate'])
                if not 0.0 <= rate <= 1.0:
                    raise ConfigError('causal_transactions_collision_rate must be between 0.0 and 1.0')
                float_inputs.append(rate)

            if 'causal_transactions_respect_early_finality' in json:
                if not isinstance(json['causal_transactions_respect_early_finality'], bool):
                    raise ConfigError('causal_transactions_respect_early_finality must be a boolean')

            if not all(isinstance(x, int) for x in inputs):
                raise ConfigError('Invalid integer parameters type')

            # Validate float parameters if any exist
            if float_inputs and not all(isinstance(x, float) for x in float_inputs):
                raise ConfigError('Invalid float parameters type')

        except KeyError as e:
            raise ConfigError(f'Malformed parameters: missing key {e}')

        except ValueError as e:
            raise ConfigError(f'Invalid parameter value: {e}')

        if not all(isinstance(x, int) for x in inputs):
            raise ConfigError('Invalid parameters type')

        self.json = json

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json, f, indent=4, sort_keys=True)


class BenchParameters:
    def __init__(self, json):
        try:
            self.faults = int(json['faults'])

            nodes = json['nodes']
            nodes = nodes if isinstance(nodes, list) else [nodes]
            if not nodes or any(x <= 1 for x in nodes):
                raise ConfigError('Missing or invalid number of nodes')
            self.nodes = [int(x) for x in nodes]

            rate = json['rate']
            rate = rate if isinstance(rate, list) else [rate]
            if not rate:
                raise ConfigError('Missing input rate')
            self.rate = [int(x) for x in rate]

            self.workers = int(json['workers'])

            if 'collocate' in json:
                self.collocate = bool(json['collocate'])
            else:
                self.collocate = True

            self.tx_size = int(json['tx_size'])

            self.duration = int(json['duration'])

            self.runs = int(json['runs']) if 'runs' in json else 1

            self.longest_causal_chain = int(json.get('longest_causal_chain', 1))
            if self.longest_causal_chain < 0:
                raise ConfigError('longest_causal_chain must be non-negative')

            if 'protocol' not in json:
                self.protocol = 'tusk'
            elif json['protocol'] == 'tusk' or json['protocol'] == 'dolphin':
                self.protocol = json['protocol']
            else:
                protocol = json['protocol']
                raise ConfigError(f'Unsupported protocol "{protocol}"')

        except KeyError as e:
            raise ConfigError(f'Malformed bench parameters: missing key {e}')

        except ValueError:
            raise ConfigError('Invalid parameters type')

        if min(self.nodes) <= self.faults:
            raise ConfigError('There should be more nodes than faults')


class PlotParameters:
    def __init__(self, json):
        try:
            faults = json['faults']
            faults = faults if isinstance(faults, list) else [faults]
            self.faults = [int(x) for x in faults] if faults else [0]

            nodes = json['nodes']
            nodes = nodes if isinstance(nodes, list) else [nodes]
            if not nodes:
                raise ConfigError('Missing number of nodes')
            self.nodes = [int(x) for x in nodes]

            workers = json['workers']
            workers = workers if isinstance(workers, list) else [workers]
            if not workers:
                raise ConfigError('Missing number of workers')
            self.workers = [int(x) for x in workers]

            if 'collocate' in json:
                self.collocate = bool(json['collocate'])
            else:
                self.collocate = True

            self.tx_size = int(json['tx_size'])

            max_lat = json['max_latency']
            max_lat = max_lat if isinstance(max_lat, list) else [max_lat]
            if not max_lat:
                raise ConfigError('Missing max latency')
            self.max_latency = [int(x) for x in max_lat]

        except KeyError as e:
            raise ConfigError(f'Malformed bench parameters: missing key {e}')

        except ValueError:
            raise ConfigError('Invalid parameters type')

        if len(self.nodes) > 1 and len(self.workers) > 1:
            raise ConfigError(
                'Either the "nodes" or the "workers can be a list (not both)'
            )

    def scalability(self):
        return len(self.workers) > 1
