import argparse
from workspace_web.app import serve

def main():
    p=argparse.ArgumentParser(prog='demo-portal',description='Infoblox NIOS-XaaS Demo browser workspace manager')
    p.add_argument('--host',default='127.0.0.1'); p.add_argument('--port',type=int,default=8787)
    a=p.parse_args(); serve(a.host,a.port)
if __name__=='__main__': main()
