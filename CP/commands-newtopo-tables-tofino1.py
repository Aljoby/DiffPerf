from ipaddress import ip_address
import socket

print ("Setup:..")

hostname = socket.gethostname()


# Configure front-panel ports
fp_ports = []

if hostname == 'tofino1a':
    fp_ports = [1,2,6,8] # front panel ports


for fp_port in fp_ports:
        for lane in range(4):
            dp = bfrt.port.port_hdl_info.get(conn_id=fp_port, chnl_id=lane, print_ents=False).data[b'$DEV_PORT']
            bfrt.port.port.add(dev_port=dp, speed='BF_SPEED_10G', fec='BF_FEC_TYP_NONE', auto_negotiation='PM_AN_FORCE_DISABLE', port_enable=True)

#multicast
active_dev_ports = [128,129,136]
bfrt.pre.node.add(multicast_node_id=0, multicast_rid=0, multicast_lag_id=[], dev_port=active_dev_ports)
bfrt.pre.mgid.add(mgid=1, multicast_node_id=[0], multicast_node_l1_xid_valid=[False], multicast_node_l1_xid=[0])



#tables
p4 = bfrt.diffperf_v16.pipe

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    
    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members

    for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'],
                        ['SELECTOR'],
                        ['ACTION_PROFILE']):
        for table in p4.info(return_info=True, print_info=False):
            if table['type'] in table_types:
                if verbose:
                    print("Clearing table {:<40} ... ".
                          format(table['full_name']), end='', flush=True)
                table['node'].clear(batch=batching)
                if verbose:
                    print('Done')
                    
#clear_all(verbose=True)

get_switch_id = p4.SwitchIngress.get_switch_id
get_switch_id.add_with_do_get_switch_id(ingress_port=136, switch_id= 1)
get_switch_id.add_with_do_get_switch_id(ingress_port=168, switch_id= 1)

get_switch_id.add_with_do_get_switch_id(ingress_port=128, switch_id= 2)
get_switch_id.add_with_do_get_switch_id(ingress_port=129, switch_id= 2)
get_switch_id.add_with_do_get_switch_id(ingress_port=184, switch_id= 2)


forward_s1 = p4.SwitchIngress.forward_s1
forward_s1.add_with_set_egr(dst_addr=0x3cfdfeb7e7f4, port=168)
forward_s1.add_with_set_egr(dst_addr=0x3cfdfead84a4, port=168)
forward_s1.add_with_set_egr(dst_addr=0x3cfdfead82e0, port=136)

forward_s2 = p4.SwitchIngress.forward_s2
forward_s2.add_with_set_egr(dst_addr=0x3cfdfeb7e7f4, port=128)
forward_s2.add_with_set_egr(dst_addr=0x3cfdfead84a4, port=129)
forward_s2.add_with_set_egr(dst_addr=0x3cfdfead82e0, port=184)

#temp  
check_diffperf_flow_Ingress = p4.SwitchIngress.Ingress_check_diffperf_flow
check_diffperf_flow_Ingress.add_with_it_is_diffperf_flow(src_addr=ip_address('10.10.10.10'), dst_addr=ip_address('10.10.10.11'), flow_id = 0 )
ip=21
id=1
for x in range(100):
    check_diffperf_flow_Ingress.add_with_it_is_diffperf_flow(src_addr=ip_address('10.10.10.10'), dst_addr=ip_address('10.10.10.'+str(ip)), flow_id = id)
    ip+=1
    id+=1


check_diffperf_flow_Egress = p4.SwitchEgressControl.Egress_check_diffperf_flow
check_diffperf_flow_Egress.add_with_is_it_diffperf_flow(src_addr=ip_address('10.10.10.10'), dst_addr=ip_address('10.10.10.11'), flow_id = 0 )
ip2=21
id2=1
for x in range(100):
    check_diffperf_flow_Egress.add_with_is_it_diffperf_flow(src_addr=ip_address('10.10.10.10'), dst_addr=ip_address('10.10.10.'+str(ip2)), flow_id = id2)
    ip2+=1
    id2+=1


diffperf_set_queue = p4.SwitchIngress.diffperf_set_queue
ip=21
for x in range(100):
    diffperf_set_queue.add_with_set_queue_id(src_addr=ip_address('10.10.10.10'), dst_addr=ip_address('10.10.10.'+str(ip)), q_id = 0)
    ip+=1


bfrt.complete_operations()

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table get_switch_id:")
get_switch_id.dump(table=True)
print ("Table forward_s1:")
forward_s1.dump(table=True)
print ("Table forward_s2:")
forward_s2.dump(table=True)
print ("Table check_diffperf_flow_Ingress:")
check_diffperf_flow_Ingress.dump(table=True)
print ("Table check_diffperf_flow_Egress:")
check_diffperf_flow_Egress.dump(table=True)
print ("Table diffperf_set_queue:")
diffperf_set_queue.dump(table=True)
                       
