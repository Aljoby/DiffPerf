/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/headers.p4"
#include "includes/parser.p4"

const int MCAST_GRP_ID = 1;

#define MAX_ACTIVE_FLOWS 100
//#define FLOW_REG_SIZE 101
#define MAX_QUEUES_PER_PORT 8
#define DIFFPERF_EGRESS_PORT 168 



control CountPackets (in bit<8> flow_id) (bit<32> FLOW_REG_SIZE) {

Register<width, instance_count>(FLOW_REG_SIZE) count_packets;

	RegisterAction <width, instance_count, width> (count_packets)
	add_packet = {
		void apply(inout width pktCount){
			pktCount = pktCount + 1;
		}
	};
	apply {
			add_packet.execute(flow_id); //store flow bytes in register
	}
}

control SwitchIngress(
    inout header_t hdr,
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm){

/*	action miss(bit<3> drop_bits) {
		ig_intr_md_for_dprsr.drop_ctl = drop_bits;
	}

	action forward(PortId_t port){
		ig_intr_md_for_tm.ucast_egress_port = port;
	}
	table l2_forward {
		key = {
			hdr.ethernet.dst_addr: exact;
		}

		actions = {
			forward;
			@defaultonly miss;
		}

		const default_action = miss(0x1);
	} 
*/

	action set_egr(PortId_t port) {
		ig_intr_md_for_tm.ucast_egress_port = port;
	}

	table forward_s1 {
		key =  {
			hdr.ethernet.dst_addr : exact;
		}
		actions = {
			set_egr; 
			NoAction;
		}
		default_action =  NoAction();
	}

	table forward_s2 {
		key = {
			hdr.ethernet.dst_addr : exact;
		}
		actions = {
			set_egr; 
			NoAction;
		}
		default_action =  NoAction();
	}

	action do_get_switch_id(bit<8> switch_id){
		meta.switch_id = switch_id;
	}
	
	table get_switch_id {
		key = {
			ig_intr_md.ingress_port: exact;
		}
		actions = {
			do_get_switch_id; 
			NoAction;
		}
		default_action =  NoAction();
	}

	action set_queue_id(bit<5> q_id){
		ig_intr_md_for_tm.qid = q_id;
	}

	table diffperf_set_queue {
		key = {
			hdr.ipv4.src_addr: exact;
			hdr.ipv4.dst_addr: exact;
		}
		actions =  {
			set_queue_id; 
			NoAction;
		}
		default_action =  NoAction();
	}


	action it_is_diffperf_flow(bit<8> flow_id){
		meta.flow_idx = flow_id;
	}


	table Ingress_check_diffperf_flow{
		key = {
			hdr.ipv4.src_addr: exact;
			hdr.ipv4.dst_addr: exact;
		}
		actions = {
			it_is_diffperf_flow;
			NoAction();
		}
		default_action = NoAction();
	}


	CountPackets(101) storcounts;

	apply {

		if(hdr.ethernet.ether_type == (bit<16>) ether_type_t.ARP){
			// do the broadcast to all involved ports
			ig_intr_md_for_tm.mcast_grp_a = MCAST_GRP_ID;
			ig_intr_md_for_tm.rid = 0;
		}
		else {
			// l2_forward.apply(); // Apply diffperf instead of the default switching
			get_switch_id.apply(); 
			if (meta.switch_id == 1){ // meta bridging
				forward_s1.apply();
				if (Ingress_check_diffperf_flow.apply().hit){
					storcounts.apply(meta.flow_idx);
				}
				else{
					NoAction();
				}

				diffperf_set_queue.apply();
			}
			else if (meta.switch_id == 2){
				forward_s2.apply();
			}
		}

		// ig_intr_md_for_tm.bypass_egress = 1w1; // uncomment to bypass egress processing
	}

}  // End of SwitchIngressControl





/*control ApplyDiffperf(in bit<8> flow_id) (bit<32> FLOW_REG_SIZE) {

Register<width, instance_count>(FLOW_REG_SIZE) flow_bytes;

	RegisterAction <width, instance_count, width> (flow_bytes)
	add_flow_bytes = {
		void apply(inout width flowbytes){
			flowbytes = flowbytes + 1;
			}
	};
	apply {
			add_flow_bytes.execute(flow_id); //store flow bytes in register
	}
}*/


control ApplyDiffperf(in bit<16> pkt_length, in bit<8> flow_id) (bit<32> FLOW_REG_SIZE) {
Register<width, instance_count>(FLOW_REG_SIZE) flow_bytes;

	RegisterAction <width, instance_count, width> (flow_bytes)
	add_flow_bytes = {
		void apply(inout width flowbytes){
			flowbytes = flowbytes + (bit<32>)pkt_length;
			//flowbytes = (bit<32>)pkt_length;
		}
	};
	apply {
		if (pkt_length != 0){
			add_flow_bytes.execute(flow_id); //store flow bytes in register
		}
	}
}

control SwitchEgressControl(
    inout header_t hdr,
    inout metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport){
	
	action is_it_diffperf_flow(bit<8> flow_id){
		meta.flow_idx = flow_id;
	}

	table Egress_check_diffperf_flow{
		key = {
			hdr.ipv4.src_addr: exact;
			hdr.ipv4.dst_addr: exact;
		}
		actions = {
			is_it_diffperf_flow;
			NoAction();
		}
		default_action = NoAction();
	}

	ApplyDiffperf(101) apply_diffperf;
	bit <16> pktLength = eg_intr_md.pkt_length;

	apply{

		if(eg_intr_md.egress_port == 0xA8){ //btlk port
			if (Egress_check_diffperf_flow.apply().hit){
				apply_diffperf.apply(pktLength,meta.flow_idx);
			}
			else{
				apply_diffperf.apply(pktLength,0x05);
				//NoAction();
			}
		}
	}

} // End of SwitchEgressControl


Pipeline(SwitchIngressParser(),
		 SwitchIngress(),
		 SwitchIngressDeparser(),
		 SwitchEgressParser(),
		 SwitchEgressControl(),
		 SwitchEgressDeparser()
		 ) pipe;

Switch(pipe) main;

