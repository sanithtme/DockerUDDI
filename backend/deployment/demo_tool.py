#!/usr/bin/env python3
import argparse, hashlib, ipaddress, json, os, secrets, string, time, sys, threading, fcntl
from pathlib import Path
import boto3, requests, yaml
from botocore.exceptions import ClientError

STATE=Path('deployment-state'); SECRETS=Path('.demo-secrets'); PLAN=Path('.pending-plan.json')
MANAGED='Infoblox-Sales-Demo'

def cfgload(p):
    with open(p,encoding='utf-8') as f:return yaml.safe_load(f) or {}
def tags(xs): return {x['Key']:x['Value'] for x in xs or []}
def safe(s): return ''.join(c if c.isalnum() or c in '._-' else '-' for c in s)[:48]
def psk():
    a=string.ascii_letters+string.digits+'._'; return 'IbDemo_'+''.join(secrets.choice(a) for _ in range(32))
def new_id(): return 'demo-'+time.strftime('%Y%m%d-%H%M%S',time.gmtime())+'-'+secrets.token_hex(3)
def spath(d): return STATE/f'{d}.json'
def kpath(d): return SECRETS/f'{d}.json'

class Progress:
    FRAMES = "|/-\\"
    def __init__(self, message):
        self.message=message; self.stop_event=threading.Event(); self.started=time.time(); self.thread=None
    def _run(self):
        i=0
        last_line=-1
        while not self.stop_event.wait(0.2):
            elapsed=int(time.time()-self.started)
            if sys.stdout.isatty():
                sys.stdout.write(f"\r  {self.FRAMES[i % len(self.FRAMES)]} {self.message}  elapsed={elapsed}s")
                sys.stdout.flush(); i+=1
            elif elapsed and elapsed % 10 == 0 and elapsed != last_line:
                print(f"  ... {self.message} elapsed={elapsed}s", flush=True); last_line=elapsed
    def __enter__(self):
        print(f"  > {self.message}")
        self.thread=threading.Thread(target=self._run,daemon=True); self.thread.start()
        return self
    def __exit__(self, exc_type, exc, tb):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=1)
        if sys.stdout.isatty():sys.stdout.write("\r" + " "*100 + "\r")
        elapsed=int(time.time()-self.started)
        print(("  OK " if exc_type is None else "  !! ")+self.message+f" ({elapsed}s)")

def ownership_name(depid): return f'Infoblox-Sales-{safe(depid)}-Endpoint'

def endpoint_owned_by(ep,depid):
    if not ep:return False
    expected=ownership_name(depid)
    if ep.get('name')==expected:return True
    tagsets=[ep.get('tags') or {}, (ep.get('universal_service') or {}).get('tags') or {}]
    return any(str(t.get('deployment-id') or t.get('DeploymentId') or '')==depid for t in tagsets)

def ownership_block(ep,depid):
    got=(ep or {}).get('name') or (ep or {}).get('id') or '<unknown endpoint>'
    raise RuntimeError(f'OWNERSHIP BLOCK: CSP endpoint {got!r} is not owned by deployment {depid}. Expected {ownership_name(depid)!r}. No CSP modification was attempted.')
def save(d,x):
    STATE.mkdir(mode=0o700,exist_ok=True)
    p=spath(d); p.write_text(json.dumps(x,indent=2)); os.chmod(p,0o600)
def load_psks(d,vpn,dry=False):
    x=os.getenv(vpn.get('pre_shared_key_env','IPSEC_PSK'))
    if x:return [x,x]
    if kpath(d).exists(): return json.loads(kpath(d).read_text())['psks']
    out=[psk(),psk()]
    if not dry:
        SECRETS.mkdir(mode=0o700,exist_ok=True); kpath(d).write_text(json.dumps({'psks':out})); os.chmod(kpath(d),0o600)
    return out

class Missing(RuntimeError): pass
class CSP:
    def __init__(self,cfg,depid,new_mode=False):
        key=os.getenv('INFOBLOX_API_KEY')
        if not key: raise RuntimeError('INFOBLOX_API_KEY is not set')
        self.cfg=cfg; self.depid=depid; self.new_mode=new_mode; self.base=cfg.get('base_url','https://csp.infoblox.com').rstrip('/')
        self.s=requests.Session(); self.s.headers.update({'Authorization':f"{cfg.get('auth_scheme','Token')} {key}",'Accept':'application/json','Content-Type':'application/json'})
    def req(self,m,p,**kw):
        r=self.s.request(m,self.base+p,timeout=kw.pop('timeout',60),**kw)
        if r.status_code==404 and 'service deployment not found' in r.text.lower(): raise Missing()
        if not r.ok: raise RuntimeError(f'CSP {m} {p}: HTTP {r.status_code}: {r.text[:700]}')
        return r.json() if r.text else {}
    def get(self,p): return self.req('GET',p)
    def post(self,p,x): return self.req('POST',p,json=x)
    def discover(self,allow_partial=False):
        ep=self.get('/api/universalinfra/v1/endpoints/').get('result',{})
        al=self.get('/api/universalinfra/v1/accesslocations').get('results') or []
        if not al and not allow_partial: raise RuntimeError('NIOS-XaaS endpoint exists but Cloud VPN access location is not ready')
        return ep,(al[0] if al else None),(ep.get('cnames') or [])
    def policy(self,name):
        xs=self.get('/api/atcfw/v1/security_policies?_fields=id,name,is_default').get('results',[])
        for x in xs:
            if name and x.get('name')==name:return str(x['id'])
        for x in xs:
            if x.get('is_default'):return str(x['id'])
        if xs:return str(xs[0]['id'])
        raise RuntimeError('No Threat Defense security policy found')
    def payload(self,region,vpn,psks,svc):
        cidrs=vpn['tunnel_inside_cidrs']; neigh=[str(next(ipaddress.ip_network(c).hosts())) for c in cidrs]
        name=f'Infoblox-Sales-{safe(self.depid)}'; creds=[f'{name}-psk1',f'{name}-psk2']
        caps=[{'type':'dns'}]
        return {'universal_service':{'operation':'CREATE','name':name,'capabilities':caps,'tags':{'managed-by':MANAGED,'deployment-id':self.depid}},
        'access_locations':{'create':[{'endpoint_id':'ref_ep','id':'ref_al','routing_type':'dynamic','type':'Cloud VPN','name':f'{name}-SITE','cloud_type':'AWS','cloud_region':region,'lan_subnets':[],'tunnel_configs':[
          {'name':'Pri','physical_tunnels':[{'path':'primary','credential_id':'ref_c1','index':0,'access_ip':'1.1.1.1','bgp_configs':[{'asn':str(vpn.get('aws_bgp_asn',64512)),'hop_limit':2,'neighbour_ips':[neigh[0]]}]}]},
          {'name':'Sec','physical_tunnels':[{'path':'secondary','credential_id':'ref_c2','index':0,'access_ip':'1.2.3.4','bgp_configs':[{'asn':str(vpn.get('aws_bgp_asn',64512)),'hop_limit':2,'neighbour_ips':[neigh[1]]}]}]}]}],'update':[],'delete':[]},
        'endpoints':{'create':[{'id':'ref_ep','name':f'{name}-Endpoint','size':self.cfg.get('endpoint_size','S'),'service_location':self.cfg['service_location'],'service_ip':svc['dns'],'neighbour_ips':svc['neighbours'],'preferred_provider':'AWS','routing_type':'dynamic','routing_config':{'bgp_config':{'asn':str(vpn.get('customer_gateway_asn',65500)),'hold_down':90,'keep_alive':30}}}],'update':[]},
        'credentials':{'create':[{'id':'ref_c1','type':'psk','name':creds[0],'value':psks[0],'cred_data':{}},{'id':'ref_c2','type':'psk','name':creds[1],'value':psks[1],'cred_data':{}}],'update':[]},'locations':{'create':[],'update':[]}}
    def ensure(self,region,vpn,psks,svc,dry=False):
        try:
            if not self.new_mode:
                ep,al,ips=self.discover()
                if ep and not endpoint_owned_by(ep,self.depid): ownership_block(ep,self.depid)
                if len(ips)>=2:return ep,al,ips[:2],False
        except Missing: pass
        if dry:
            print(f"PLAN CSP: create NIOS-XaaS at {self.cfg['service_location']} DNS={svc['dns']} neighbours={','.join(svc['neighbours'])}")
            return {'service_ip':svc['dns']},None,['<pop1>','<pop2>'],True
        x=self.payload(region,vpn,psks,svc)
        try:self.post('/api/universalinfra/v1/consolidated/configure',x)
        except RuntimeError as e:
            if 'duplicate key name' not in str(e).lower():raise
            suf=secrets.token_hex(3)
            for c in x['credentials']['create']: c['name']+='-'+suf
            self.post('/api/universalinfra/v1/consolidated/configure',x)
        deadline=time.time()+int(self.cfg.get('provision_timeout_seconds',900))
        while time.time()<deadline:
            try:
                ep,al,ips=self.discover()
                if len(ips)>=2:return ep,al,ips[:2],True
            except (Missing,RuntimeError):pass
            time.sleep(int(self.cfg.get('poll_interval_seconds',20)))
        raise RuntimeError('Timed out waiting for NIOS-XaaS/Cloud Service IPs')
    def update(self,ep,al,outside_ips,services,tunnel_cidrs=None):
        if not endpoint_owned_by(ep,self.depid): ownership_block(ep,self.depid)
        if not al: raise RuntimeError('CSP access location is missing; refusing tunnel update')
        pri,sec=al['tunnel_configs'][:2]; pp=pri['physical_tunnels'][0]; sp=sec['physical_tunnels'][0]
        alc={'endpoint_id':ep['id'].split('/')[-1],'id':al['id'].split('/')[-1],'routing_type':'dynamic','type':'Cloud VPN','name':al['name'],'cloud_type':al['cloud_type'],'cloud_region':al['cloud_region'],'lan_subnets':[],'tunnel_configs':[]}
        for idx,(t,p,ip) in enumerate(((pri,pp,outside_ips[0]),(sec,sp,outside_ips[1]))):
            b=p['bgp_configs'][0]
            bg={'id':b['id'],'asn':b.get('asn',64512),'hop_limit':b.get('hop_limit',2)}
            if tunnel_cidrs:
                bg['cloud_cidr']=tunnel_cidrs[idx]
            elif 'cloud_cidr' in b:
                bg['cloud_cidr']=b['cloud_cidr']
            alc['tunnel_configs'].append({'id':t['id'],'name':t['name'],'physical_tunnels':[{'path':p['path'],'credential_id':p['credential_id'],'index':0,'access_ip':ip,'bgp_configs':[bg]}]})
        caps=[]
        if services.get('dns_enabled',True):caps.append({'type':'dns','profile_id':''})
        if services.get('dhcp_enabled',True):caps.append({'type':'dhcp','profile_id':''})
        if services.get('threat_defense_enabled',True):caps.append({'type':'dfp','profile_id':self.policy(services.get('security_policy'))})
        e={k:ep[k] for k in ('name','size','service_location','service_ip','neighbour_ips','preferred_provider','routing_type','routing_config') if k in ep};e['id']=ep['id'].split('/')[-1];e['tags']={}
        p={'universal_service':{'operation':'UPDATE','id':ep['universal_service_id'],'name':ep.get('name','Sales-Demo'),'description':'','capabilities':caps,'tags':{}},'access_locations':{'create':[],'update':[alc],'delete':[]},'endpoints':{'create':[],'update':[e],'delete':[]},'credentials':{'create':[],'update':[]},'locations':{'create':[],'update':[]}}
        self.post('/api/universalinfra/v1/consolidated/configure',p)

class Platform:
    def __init__(self,cfg,vpn):
        self.cfg=cfg; self.vpn=vpn; self.region=cfg['aws_region']; self.s=boto3.Session(region_name=self.region); self.ec2=self.s.client('ec2'); self.sts=self.s.client('sts')
    def used_service_networks(self):
        used=set()
        # AWS tags are the shared inventory. CGWs are tenant-specific and survive for the life of a deployment.
        for x in self.ec2.describe_customer_gateways(Filters=[{'Name':'tag:ManagedBy','Values':[MANAGED]}]).get('CustomerGateways',[]):
            if x.get('State')=='deleted': continue
            n=tags(x.get('Tags')).get('ServiceNetwork')
            if n: used.add(n)
        # Dedicated clients carry the same tag and make inventory visible even during later deployment phases.
        rs=self.ec2.describe_instances(Filters=[{'Name':'tag:ManagedBy','Values':[MANAGED]},{'Name':'instance-state-name','Values':['pending','running','stopping','stopped']}]).get('Reservations',[])
        for r in rs:
            for x in r.get('Instances',[]):
                n=tags(x.get('Tags')).get('ServiceNetwork')
                if n: used.add(n)
        for st in active_states():
            n=(st.get('service_network') or {}).get('cidr')
            if n: used.add(n)
        return used
    def reserve_service(self,depid,dry=False,planned=None):
        if planned:
            return planned
        pool=ipaddress.ip_network(self.cfg['service_network_pool']['cidr']); prefix=int(self.cfg['service_network_pool'].get('prefix',24)); used=self.used_service_networks()
        for n in pool.subnets(new_prefix=prefix):
            if str(n) in used: continue
            hs=list(n.hosts()); return {'cidr':str(n),'dns':str(hs[2]),'neighbours':[str(hs[3]),str(hs[4])]}
        raise RuntimeError('No free NIOS-X service network in platform pool')
    def used_tunnel_cidrs(self):
        used=set()
        # AWS is authoritative for tunnel-inside CIDRs already allocated on this account/region.
        for x in self.ec2.describe_vpn_connections().get('VpnConnections',[]):
            if x.get('State')=='deleted': continue
            for t in (x.get('Options',{}).get('TunnelOptions') or []):
                c=t.get('TunnelInsideCidr')
                if c: used.add(str(ipaddress.ip_network(c,strict=False)))
        # Persisted state protects allocations while a deployment is being retried.
        for st in active_states():
            for c in st.get('tunnel_inside_cidrs',[]) or []:
                if c: used.add(str(ipaddress.ip_network(c,strict=False)))
        return used
    def reserve_tunnel_cidrs(self,depid,planned=None,count=2):
        if planned and len(planned)>=count:
            return planned[:count]
        used=self.used_tunnel_cidrs(); out=[]
        # Keep allocations in AWS's 169.254/16 link-local space and on /30 boundaries.
        # Start at the reference lab range (third octet 21) and skip anything already in use.
        for third in range(21,255):
            c=f'169.254.{third}.0/30'
            n=str(ipaddress.ip_network(c,strict=False))
            if n in used or n in out: continue
            out.append(n)
            if len(out)==count:return out
        raise RuntimeError('No free AWS VPN tunnel inside /30 CIDRs found in allocation pool')
    def shared(self,dry=False):
        c=self.cfg['shared_vpc']; name=c.get('name',MANAGED)
        xs=self.ec2.describe_vpcs(Filters=[{'Name':'tag:Name','Values':[name]},{'Name':'tag:ManagedBy','Values':[MANAGED]}]).get('Vpcs',[])
        if not xs:
            # Also adopt an existing VPC with the configured CIDR; tag it so future discovery is deterministic.
            xs=self.ec2.describe_vpcs(Filters=[{'Name':'cidr-block','Values':[c['cidr']]}]).get('Vpcs',[])
        if xs: vid=xs[0]['VpcId']
        elif dry: return {'vpc_id':'<new-shared-vpc>','subnet_id':'<new-shared-subnet>','route_table_ids':['<new-shared-rt>']}
        else:
            t=[{'Key':'Name','Value':name},{'Key':'ManagedBy','Value':MANAGED},{'Key':'Platform','Value':'shared'}]; vid=self.ec2.create_vpc(CidrBlock=c['cidr'],TagSpecifications=[{'ResourceType':'vpc','Tags':t}])['Vpc']['VpcId']; self.ec2.get_waiter('vpc_available').wait(VpcIds=[vid]); self.ec2.modify_vpc_attribute(VpcId=vid,EnableDnsSupport={'Value':True}); self.ec2.modify_vpc_attribute(VpcId=vid,EnableDnsHostnames={'Value':True})
        subs=self.ec2.describe_subnets(Filters=[{'Name':'vpc-id','Values':[vid]},{'Name':'tag:Platform','Values':['shared-client']}]).get('Subnets',[])
        if not subs:
            subs=self.ec2.describe_subnets(Filters=[{'Name':'vpc-id','Values':[vid]},{'Name':'cidr-block','Values':[c['client_subnet_cidr']]}]).get('Subnets',[])
        if subs: sid=subs[0]['SubnetId']
        elif dry: sid='<new-shared-subnet>'
        else:
            t=[{'Key':'ManagedBy','Value':MANAGED},{'Key':'Platform','Value':'shared-client'}]; sid=self.ec2.create_subnet(VpcId=vid,CidrBlock=c['client_subnet_cidr'],TagSpecifications=[{'ResourceType':'subnet','Tags':t}])['Subnet']['SubnetId']; self.ec2.modify_subnet_attribute(SubnetId=sid,MapPublicIpOnLaunch={'Value':True})
        # Prefer the route table explicitly associated with the selected subnet.
        rts=[] if sid.startswith('<') else self.ec2.describe_route_tables(Filters=[{'Name':'association.subnet-id','Values':[sid]}]).get('RouteTables',[])
        if not rts:
            rts=self.ec2.describe_route_tables(Filters=[{'Name':'vpc-id','Values':[vid]},{'Name':'tag:Platform','Values':['shared-client']}]).get('RouteTables',[])
        if not rts and not sid.startswith('<'):
            # If the subnet uses the VPC main route table, discover that rather than creating a duplicate.
            rts=self.ec2.describe_route_tables(Filters=[{'Name':'vpc-id','Values':[vid]},{'Name':'association.main','Values':['true']}]).get('RouteTables',[])
        if rts: rt=rts[0]['RouteTableId']
        elif dry: rt='<new-shared-rt>'
        else:
            igs=self.ec2.describe_internet_gateways(Filters=[{'Name':'attachment.vpc-id','Values':[vid]}]).get('InternetGateways',[])
            if igs: igw=igs[0]['InternetGatewayId']
            else: igw=self.ec2.create_internet_gateway(TagSpecifications=[{'ResourceType':'internet-gateway','Tags':[{'Key':'ManagedBy','Value':MANAGED}]}])['InternetGateway']['InternetGatewayId']; self.ec2.attach_internet_gateway(InternetGatewayId=igw,VpcId=vid)
            rt=self.ec2.create_route_table(VpcId=vid,TagSpecifications=[{'ResourceType':'route-table','Tags':[{'Key':'ManagedBy','Value':MANAGED},{'Key':'Platform','Value':'shared-client'}]}])['RouteTable']['RouteTableId']; self.ec2.create_route(RouteTableId=rt,DestinationCidrBlock='0.0.0.0/0',GatewayId=igw); self.ec2.associate_route_table(RouteTableId=rt,SubnetId=sid)
        if not dry and xs:
            try:self.ec2.create_tags(Resources=[vid,sid,rt],Tags=[{'Key':'ManagedBy','Value':MANAGED}])
            except ClientError:pass
        return {'vpc_id':vid,'subnet_id':sid,'route_table_ids':[rt]}

class AWS:
    def __init__(self,p,vpn,env): self.p=p;self.vpn_cfg=vpn;self.env=env;self.ec2=p.ec2;self.region=p.region
    def vgw(self,dry=False):
        vid=self.env['vpc_id']; xs=self.ec2.describe_vpn_gateways(Filters=[{'Name':'attachment.vpc-id','Values':[vid]}]).get('VpnGateways',[])
        for x in xs:
            if x.get('State')!='deleted' and tags(x.get('Tags')).get('ManagedBy')==MANAGED:return x['VpnGatewayId']
        if dry:return '<new-vgw>'
        g=self.ec2.create_vpn_gateway(Type='ipsec.1',AmazonSideAsn=int(self.vpn_cfg.get('aws_bgp_asn',64512)),TagSpecifications=[{'ResourceType':'vpn-gateway','Tags':[{'Key':'ManagedBy','Value':MANAGED},{'Key':'Platform','Value':'shared'}]}])['VpnGateway']['VpnGatewayId'];time.sleep(8);self.ec2.attach_vpn_gateway(VpnGatewayId=g,VpcId=vid)
        for _ in range(36):
            x=self.ec2.describe_vpn_gateways(VpnGatewayIds=[g])['VpnGateways'][0]
            if any(a.get('VpcId')==vid and a.get('State')=='attached' for a in x.get('VpcAttachments',[])):return g
            time.sleep(5)
        raise RuntimeError('VGW attachment timeout')
    def cgw(self,ip,depid,dry=False):
        for x in self.ec2.describe_customer_gateways(Filters=[{'Name':'ip-address','Values':[ip]}]).get('CustomerGateways',[]):
            if x.get('State')!='deleted' and tags(x.get('Tags')).get('DeploymentId')==depid:return x['CustomerGatewayId']
        if dry:return '<new-cgw>'
        return self.ec2.create_customer_gateway(BgpAsn=int(self.vpn_cfg.get('customer_gateway_asn',65500)),PublicIp=ip,Type='ipsec.1',TagSpecifications=[{'ResourceType':'customer-gateway','Tags':[{'Key':'ManagedBy','Value':MANAGED},{'Key':'DeploymentId','Value':depid},{'Key':'ServiceNetwork','Value':self.env['service_network']},{'Key':'Owner','Value':os.environ.get('INFOBLOX_DEMO_OWNER',os.environ.get('USER','unknown'))}]}])['CustomerGateway']['CustomerGatewayId']
    def vpn(self,cgw,vgw,cidr,key,depid,i,dry=False):
        # Resume/reconcile by deployment ownership first. POP IP changes can create a new
        # CGW, but an existing VPN for this deployment/tunnel must never be recreated.
        owned=self.ec2.describe_vpn_connections(Filters=[{'Name':'tag:DeploymentId','Values':[depid]}]).get('VpnConnections',[])
        expected_name=f'{depid}-vpn{i}'
        candidates=[]
        for x in owned:
            if x.get('State')=='deleted': continue
            t=tags(x.get('Tags'))
            if t.get('ManagedBy')!=MANAGED: continue
            if t.get('Name')==expected_name: return x['VpnConnectionId']
            candidates.append(x)
        # Legacy deployments may not have a Name/Owner tag. Match the saved tunnel CIDR.
        for x in candidates:
            opts=x.get('Options',{}).get('TunnelOptions',[])
            if any(z.get('TunnelInsideCidr')==cidr for z in opts): return x['VpnConnectionId']
        # Older AWS responses may omit TunnelInsideCidr from Options; when exactly two
        # deployment-owned VPNs exist, preserve deterministic vpn1/vpn2 ordering by Name
        # where available and otherwise by VPN id.
        if len(candidates)==2 and all(not tags(x.get('Tags')).get('Name') for x in candidates):
            return sorted(candidates,key=lambda x:x['VpnConnectionId'])[i-1]['VpnConnectionId']
        # Backward-compatible exact CGW/VGW lookup.
        for x in self.ec2.describe_vpn_connections(Filters=[{'Name':'customer-gateway-id','Values':[cgw]},{'Name':'vpn-gateway-id','Values':[vgw]}]).get('VpnConnections',[]):
            t=tags(x.get('Tags'))
            if x.get('State')!='deleted' and t.get('DeploymentId')==depid and t.get('ManagedBy')==MANAGED:return x['VpnConnectionId']
        if dry:return '<new-vpn>'
        for attempt in range(4):
            try:return self.ec2.create_vpn_connection(CustomerGatewayId=cgw,VpnGatewayId=vgw,Type='ipsec.1',Options={'StaticRoutesOnly':False,'TunnelOptions':[{'TunnelInsideCidr':cidr,'PreSharedKey':key,'StartupAction':'start'}]},TagSpecifications=[{'ResourceType':'vpn-connection','Tags':[{'Key':'ManagedBy','Value':MANAGED},{'Key':'DeploymentId','Value':depid},{'Key':'Name','Value':expected_name},{'Key':'Owner','Value':os.environ.get('INFOBLOX_DEMO_OWNER',os.environ.get('USER','unknown'))}]}])['VpnConnection']['VpnConnectionId']
            except ClientError as e:
                code=e.response.get('Error',{}).get('Code')
                if code=='InvalidCidr.InUse':
                    # Rediscover before failing: same deployment => reuse; foreign/unknown => block safely.
                    again=self.ec2.describe_vpn_connections(Filters=[{'Name':'tag:DeploymentId','Values':[depid]}]).get('VpnConnections',[])
                    for x in again:
                        if x.get('State')!='deleted' and tags(x.get('Tags')).get('ManagedBy')==MANAGED:
                            if tags(x.get('Tags')).get('Name')==expected_name:return x['VpnConnectionId']
                    raise RuntimeError(f'RECONCILIATION BLOCKED: tunnel CIDR {cidr} is already in use and no matching deployment-owned VPN could be verified. No duplicate VPN was created.') from None
                if code!='InvalidVpnGatewayID.NotFound' or attempt==3:raise
                time.sleep(15)
    def outside(self,v):
        for _ in range(36):
            x=self.ec2.describe_vpn_connections(VpnConnectionIds=[v])['VpnConnections'][0];ts=x.get('Options',{}).get('TunnelOptions',[])
            if ts and ts[0].get('OutsideIpAddress'):return ts[0]['OutsideIpAddress']
            time.sleep(5)
        raise RuntimeError('VPN outside IP timeout')
    def wait_bgp(self,vpns,timeout=600):
        deadline=time.time()+timeout
        while time.time()<deadline:
            ready=True; telemetry=[]
            for v in vpns:
                x=self.ec2.describe_vpn_connections(VpnConnectionIds=[v])['VpnConnections'][0]
                ts=x.get('VgwTelemetry',[])
                first=ts[0] if ts else {}
                telemetry.append({'vpn':v,'outside_ip':first.get('OutsideIpAddress'),'status':first.get('Status'),'routes':first.get('AcceptedRouteCount',0),'message':first.get('StatusMessage')})
                if first.get('Status')!='UP' or int(first.get('AcceptedRouteCount',0) or 0)<1: ready=False
            if ready:return telemetry
            time.sleep(15)
        raise RuntimeError('BGP readiness timeout: selected AWS tunnels did not reach UP with learned routes. Last telemetry: '+json.dumps(telemetry))
    def propagate(self,vgw,dry=False):
        for rt in self.env['route_table_ids']:
            if dry:print('PLAN route propagation:',rt);continue
            x=self.ec2.describe_route_tables(RouteTableIds=[rt])['RouteTables'][0]
            if not any(z.get('GatewayId')==vgw for z in x.get('PropagatingVgws',[])):self.ec2.enable_vgw_route_propagation(RouteTableId=rt,GatewayId=vgw)
    def client(self,depid,dns,dry=False):
        xs=self.ec2.describe_instances(Filters=[{'Name':'tag:DeploymentId','Values':[depid]},{'Name':'instance-state-name','Values':['pending','running','stopped']}]).get('Reservations',[])
        if xs:return xs[0]['Instances'][0]['InstanceId']
        if dry:return '<new-client>'
        sg=self.ec2.create_security_group(GroupName=f'{depid}-client',Description='Infoblox Sales demo client',VpcId=self.env['vpc_id'])['GroupId'];self.ec2.create_tags(Resources=[sg],Tags=[{'Key':'ManagedBy','Value':MANAGED},{'Key':'DeploymentId','Value':depid},{'Key':'Owner','Value':os.environ.get('INFOBLOX_DEMO_OWNER',os.environ.get('USER','unknown'))}])
        ami=self.p.s.client('ssm').get_parameter(Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64')['Parameter']['Value'];profile=self.p.cfg.get('client_instance_profile_name')
        ud=f'''#!/bin/bash\ndnf install -y bind-utils jq\ncat >/usr/local/bin/ibdig <<'EOF'\n#!/bin/bash\nexec dig @{dns} "$@"\nEOF\nchmod +x /usr/local/bin/ibdig\necho "NIOS-XaaS DNS: {dns} (use: ibdig example.com)" >/etc/motd\n'''
        kw={'ImageId':ami,'InstanceType':self.p.cfg.get('client_instance_type','t3.micro'),'SubnetId':self.env['subnet_id'],'SecurityGroupIds':[sg],'MinCount':1,'MaxCount':1,'UserData':ud,'TagSpecifications':[{'ResourceType':'instance','Tags':[{'Key':'ManagedBy','Value':MANAGED},{'Key':'DeploymentId','Value':depid},{'Key':'ServiceNetwork','Value':self.env['service_network']},{'Key':'Name','Value':f'{depid}-client'},{'Key':'Owner','Value':os.environ.get('INFOBLOX_DEMO_OWNER',os.environ.get('USER','unknown'))}]}]}
        if profile:kw['IamInstanceProfile']={'Name':profile}
        iid=self.ec2.run_instances(**kw)['Instances'][0]['InstanceId'];return iid

def validate(c):
    for k in ('platform','infoblox','vpn','services'):
        if k not in c:raise RuntimeError(f'Missing config section {k}')
    if not c['platform'].get('aws_region'):raise RuntimeError('platform.aws_region required')
    if not c['infoblox'].get('service_location'):raise RuntimeError('infoblox.service_location required')

def active_states():
    if not STATE.exists():return []
    out=[]
    for p in STATE.glob('*.json'):
        try:
            x=json.loads(p.read_text())
            if x.get('phase')!='cleaned':out.append(x)
        except:pass
    return out

def doctor(a):
    c=cfgload(a.config);validate(c);p=Platform(c['platform'],c['vpn']);ident=p.sts.get_caller_identity();env=p.shared(dry=True);CSP(c['infoblox'],'doctor').policy(c['services'].get('security_policy')) if c['services'].get('threat_defense_enabled',True) else None
    print(f"DOCTOR OK AWS={ident['Account']} region={p.region} shared_vpc={env['vpc_id']} CSP=Token DNS={c['services'].get('dns_enabled',True)} DHCP={c['services'].get('dhcp_enabled',True)} TD={c['services'].get('threat_defense_enabled',True)}")

def _load_state(depid):
    if not depid or not spath(depid).exists(): return None
    try: return json.loads(spath(depid).read_text())
    except Exception: return None

def _select_deployment(a):
    pending=None
    if PLAN.exists():
        try: pending=json.loads(PLAN.read_text())
        except Exception: pending=None
    if a.new and a.deployment_id:
        raise RuntimeError('Use either --new or --deployment-id, not both')
    if a.deployment_id:
        return a.deployment_id,pending,False
    if a.new:
        return new_id(),None,True
    if pending and pending.get('deployment_id'):
        return pending['deployment_id'],pending,False
    active=active_states()
    if len(active)==1:
        return active[0]['deployment_id'],None,False
    if len(active)>1:
        raise RuntimeError('Multiple active deployments exist. Use --deployment-id to choose one, or --new to intentionally create another deployment.')
    raise RuntimeError('No resumable deployment found. Use deploy --new (or deploy --dry-run --new) to intentionally create a new deployment.')

def _checkpoint(depid,phase,base=None,**updates):
    st=dict(base or _load_state(depid) or {})
    st.update(updates); st['deployment_id']=depid; st['phase']=phase; save(depid,st); return st

def _lock_for(depid):
    STATE.mkdir(exist_ok=True)
    fp=(STATE/f'{depid}.lock').open('w')
    try: fcntl.flock(fp.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        fp.close(); raise RuntimeError(f'DEPLOYMENT ALREADY RUNNING: {depid}. No changes made.')
    fp.write(str(os.getpid())); fp.flush(); return fp

def _deployment_running(depid):
    lp=STATE/f'{depid}.lock'
    if not lp.exists(): return False,None
    fp=lp.open('r+')
    try:
        fcntl.flock(fp.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        fcntl.flock(fp.fileno(),fcntl.LOCK_UN); fp.close(); return False,None
    except BlockingIOError:
        try: pid=lp.read_text().strip()
        except Exception: pid='unknown'
        fp.close(); return True,pid

def deploy(a):
    c=cfgload(a.config); validate(c); p=Platform(c['platform'],c['vpn']); env=p.shared(dry=a.dry_run)
    depid,pending,is_new=_select_deployment(a)
    lockfp=_lock_for(depid) if not a.dry_run else None
    existing_state=_load_state(depid)
    existing_svc=(existing_state or {}).get('service_network')
    planned_svc=existing_svc or ((pending or {}).get('service_network') if (pending or {}).get('deployment_id')==depid else None)
    svc=p.reserve_service(depid,dry=a.dry_run,planned=planned_svc)
    existing_tunnels=(existing_state or {}).get('tunnel_inside_cidrs')
    planned_tunnels=existing_tunnels or ((pending or {}).get('tunnel_inside_cidrs') if (pending or {}).get('deployment_id')==depid else None)
    tunnel_cidrs=p.reserve_tunnel_cidrs(depid,planned=planned_tunnels)
    vpn_cfg=dict(c['vpn']); vpn_cfg['tunnel_inside_cidrs']=tunnel_cidrs
    env['service_network']=svc['cidr']
    cc=dict(c['infoblox']); cc.update({'universal_service_name':f'Infoblox-NIOS-XaaS-{safe(depid)}','service_ip':svc['dns'],'service_neighbour_ips':svc['neighbours']}); cs=CSP(cc,depid,new_mode=is_new)
    # Resume is strict; --new intentionally ignores unrelated existing CSP deployments.
    if not is_new:
        try:
            old_ep,_,_=cs.discover(allow_partial=True)
            if old_ep:
                if not endpoint_owned_by(old_ep,depid): ownership_block(old_ep,depid)
                if not kpath(depid).exists() and not os.getenv(c['vpn'].get('pre_shared_key_env','IPSEC_PSK')) and not a.dry_run:
                    raise RuntimeError('Matching CSP deployment exists but its persisted PSKs are unavailable. Refusing to generate replacements. Restore .demo-secrets for this deployment or provide the known IPSEC_PSK.')
        except Missing:
            pass
    if a.dry_run:
        PLAN.write_text(json.dumps({'deployment_id':depid,'service_network':svc,'tunnel_inside_cidrs':tunnel_cidrs,'region':p.region,'vpc_id':env['vpc_id']},indent=2))
    keys=load_psks(depid,c['vpn'],a.dry_run)
    print('Deployment ID:',depid); print('Mode:','NEW' if is_new else 'RECONCILE/RESUME'); print('Shared VPC:',env['vpc_id']); print('Shared subnet:',env['subnet_id']); print('Route table(s):',', '.join(env['route_table_ids'])); print('Allocated service network:',svc['cidr'],'DNS:',svc['dns']); print('Tunnel inside CIDRs:',', '.join(tunnel_cidrs))
    if a.dry_run:
        ep,al,pops,created=cs.ensure(p.region,vpn_cfg,keys,svc,True); aw=AWS(p,vpn_cfg,env); vgw=aw.vgw(True); aw.propagate(vgw,True); aw.client(depid,(ep or {}).get('service_ip',svc['dns']),True)
        print('PLAN: NIOS-XaaS + DNS/DHCP/TD + CGWs/VPNs/BGP + dedicated client; no changes made'); print('PLAN SAVED: real deploy will reuse this deployment ID, service network, and tunnel CIDRs'); return
    st=_checkpoint(depid,'planned',existing_state,region=p.region,vpc_id=env['vpc_id'],subnet_id=env['subnet_id'],route_table_ids=env['route_table_ids'],service_network=svc,tunnel_inside_cidrs=tunnel_cidrs)
    with Progress('Provisioning/reconciling NIOS-XaaS service and waiting for service IPs'):
        ep,al,pops,created=cs.ensure(p.region,vpn_cfg,keys,svc,False)
    st=_checkpoint(depid,'csp-ready',st,service_ip=ep.get('service_ip'),pop_ips=pops,csp_created=created)
    aw=AWS(p,vpn_cfg,env); vgw=aw.vgw(False); cg=[]; vp=[]; outs=[]
    for i,ip in enumerate(pops):
        g=aw.cgw(ip,depid,False); v=aw.vpn(g,vgw,tunnel_cidrs[i],keys[i],depid,i+1,False); cg.append(g); vp.append(v); outs.append(aw.outside(v))
    st=_checkpoint(depid,'aws-vpn-ready',st,vgw_id=vgw,customer_gateway_ids=cg,vpn_connection_ids=vp,aws_outside_ips=outs)
    aw.propagate(vgw,False); client=aw.client(depid,ep.get('service_ip',svc['dns']),False)
    st=_checkpoint(depid,'client-ready',st,client_instance_id=client)
    with Progress('Updating CSP tunnel endpoints with AWS outside IPs'):
        cs.update(ep,al,outs,c['services'],tunnel_cidrs=tunnel_cidrs)
    print('  OK CSP primary and secondary AWS outside tunnel IPs updated.')
    st=_checkpoint(depid,'csp-tunnels-updated',st)
    try:
        with Progress('Waiting for selected IPsec/BGP tunnels to reach UP and learn routes'):
            telemetry=aw.wait_bgp(vp,timeout=int(c['infoblox'].get('provision_timeout_seconds',900)))
    except RuntimeError as e:
        if 'BGP readiness timeout' in str(e):
            telemetry=[]
            for v in vp:
                x=aw.ec2.describe_vpn_connections(VpnConnectionIds=[v])['VpnConnections'][0]
                first=(x.get('VgwTelemetry') or [{}])[0]
                telemetry.append({'vpn':v,'outside_ip':first.get('OutsideIpAddress'),'status':first.get('Status'),'routes':first.get('AcceptedRouteCount',0),'message':first.get('StatusMessage')})
            _checkpoint(depid,'bgp-attention',st,vpn_telemetry=telemetry,last_error='BGP readiness timeout',last_updated_at=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
            print('\n⚠ BGP ATTENTION REQUIRED', flush=True)
            for i,t in enumerate(telemetry,1): print(f"  Tunnel {i}: IPsec={t.get('message')} BGP={t.get('status')} routes={t.get('routes',0)}", flush=True)
            print('Deployment state preserved. Correct connectivity/BGP and resume with: demo deploy', flush=True)
            return
        raise
    st=_checkpoint(depid,'ready',st,vpn_telemetry=telemetry,last_updated_at=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
    if PLAN.exists(): PLAN.unlink()
    print('DEMO READY deployment=',depid,'client=',client,'dns=',st['service_ip'])

def status(a):
    xs=active_states()
    if a.deployment_id:xs=[x for x in xs if x.get('deployment_id')==a.deployment_id]
    if not xs: print('No active deployments'); return
    order=['planned','csp-ready','aws-vpn-ready','client-ready','csp-tunnels-updated','ready']
    labels=[('Plan','planned'),('NIOS-XaaS','csp-ready'),('AWS VPN','aws-vpn-ready'),('Demo client','client-ready'),('Tunnel endpoints','csp-tunnels-updated'),('BGP / routes','ready')]
    for x in xs:
        phase=x.get('phase','unknown'); running,pid=_deployment_running(x.get('deployment_id'))
        print('Infoblox NIOS-XaaS Demo Status'); print('-'*52)
        print('Deployment :',x.get('deployment_id')); print('Owner      :',os.environ.get('INFOBLOX_DEMO_OWNER','workspace'))
        print('Service IP :',x.get('service_ip') or (x.get('service_network') or {}).get('dns','pending'))
        print('Process    :',('RUNNING (PID '+str(pid)+')') if running else 'NOT RUNNING / resumable')
        try: idx=order.index(phase)
        except ValueError: idx=-1
        for label,key in labels:
            if phase=='bgp-attention' and key=='ready': mark='⚠'
            elif key in order and order.index(key)<=idx: mark='✓'
            elif running and key in order and order.index(key)==idx+1: mark='⠋'
            else: mark='○'
            print(f'{mark} {label}')
        tel=x.get('vpn_telemetry') or []
        for i,t in enumerate(tel,1): print(f"  Tunnel {i}: status={t.get('status')} routes={t.get('routes',0)} {t.get('message','')}")
        if phase=='ready': print('Result     : ✓ DEMO READY')
        elif phase=='bgp-attention': print('Result     : ⚠ BGP ATTENTION REQUIRED — state preserved; resume with demo deploy')
        else: print('Result     : deployment/reconciliation in progress')
        if x.get('last_error'): print('Last error :',x.get('last_error'))
        print()

def cleanup(a):
    c=cfgload(a.config);validate(c);xs=active_states()
    if a.deployment_id:xs=[x for x in xs if x.get('deployment_id')==a.deployment_id]
    if len(xs)!=1:
        print('Specify --deployment-id. Active:',', '.join(x['deployment_id'] for x in xs));return
    st=xs[0];p=Platform(c['platform'],c['vpn']);ec2=p.ec2
    for v in st.get('vpn_connection_ids',[]):
        try:ec2.delete_vpn_connection(VpnConnectionId=v)
        except ClientError:pass
    time.sleep(10)
    for g in st.get('customer_gateway_ids',[]):
        try:ec2.delete_customer_gateway(CustomerGatewayId=g)
        except ClientError:pass
    iid=st.get('client_instance_id')
    if iid:
        try:
            ec2.terminate_instances(InstanceIds=[iid]); ec2.get_waiter('instance_terminated').wait(InstanceIds=[iid])
        except ClientError:pass
    for sg in ec2.describe_security_groups(Filters=[{'Name':'tag:DeploymentId','Values':[st['deployment_id']]}]).get('SecurityGroups',[]):
        try:ec2.delete_security_group(GroupId=sg['GroupId'])
        except ClientError:pass
    st['phase']='cleaned'; st['cleaned_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    save(st['deployment_id'],st)
    if kpath(st['deployment_id']).exists(): kpath(st['deployment_id']).unlink()
    print('Cleaned tenant-specific AWS/client allocation. Shared VPC/VGW retained.')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--config',default='config.yaml');sp=ap.add_subparsers(dest='cmd',required=True)
    x=sp.add_parser('doctor');x.set_defaults(fn=doctor)
    x=sp.add_parser('deploy');x.add_argument('--dry-run',action='store_true');x.add_argument('--deployment-id');x.add_argument('--new',action='store_true',help='intentionally create a new deployment instead of resuming/reconciling');x.set_defaults(fn=deploy)
    x=sp.add_parser('status');x.add_argument('--deployment-id');x.set_defaults(fn=status)
    x=sp.add_parser('cleanup');x.add_argument('--deployment-id');x.set_defaults(fn=cleanup)
    a=ap.parse_args()
    try:
        a.fn(a)
    except KeyboardInterrupt:
        print('\nDeployment interrupted. Checkpointed resources were not deleted.')
        print('Next: demo status, then resume with: demo deploy')
        print('IMPORTANT: do not use --new to resume.')
        raise SystemExit(130)
    except RuntimeError as e:
        print(f'ERROR: {e}', file=sys.stderr, flush=True)
        raise SystemExit(2)
if __name__=='__main__':main()
