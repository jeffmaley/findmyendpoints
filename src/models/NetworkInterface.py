class NetworkInterface(object):
    def __init__(self, id=None):
        self.security_groups = {}
        self.public_dns = None
        self.association_id = None
        self.allocation_id = None
        self.public_ip = None
        self.id = id
        self.instance_name = None
        self.instance_id = None
        self.region = None
        self.account_id = None
