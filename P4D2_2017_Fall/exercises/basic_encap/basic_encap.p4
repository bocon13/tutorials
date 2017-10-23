/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TUNNEL_MAGIC = 0xABCD;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header myTunnel_t {
    bit<16> magic;
    bit<48> id;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    myTunnel_t   myTunnel;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(packet.lookahead<bit<16>>()) {
            TUNNEL_MAGIC: parse_myTunnel;
            default: parse_ethernet;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(in headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action tunnel_ingress(bit<48> id) {
        hdr.myTunnel.setValid();
        hdr.myTunnel.magic = TUNNEL_MAGIC;
        hdr.myTunnel.id = id;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            tunnel_ingress;
            drop;
        }
        size = 1024;
        const default_action = drop();
    }
    
    //TODO(BOC) should this look more like a L2 or L3 forwarding element?
    action tunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        //TODO hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action tunnel_egress(/*TODO(BOC) macAddr_t dstAddr,*/ egressSpec_t port) {
        standard_metadata.egress_spec = port;
        //TODO(BOC) hdr.ethernet.dstAddr = dstAddr;
        hdr.myTunnel.setInvalid();
        //TODO(BOC) hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    direct_counter(CounterType.packets_and_bytes) tunnelCount;

    table myTunnelTable {
        key = {
            hdr.myTunnel.id: exact;
        }
        actions = {
            tunnel_forward;
            tunnel_egress;
            drop;
        }
        counters = tunnelCount;
        const default_action = drop();
    }

    apply {
        if (!hdr.myTunnel.isValid()) {
            ipv4_lpm.apply();
        }
        myTunnelTable.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
