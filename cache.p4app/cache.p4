/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROT_UDP  = 0x11;
const bit<16> KVP_PORT  = 1234;

// ================== Headers ================== 

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header udp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   length;
    bit<16>   csum;
}

header kvp_req_t {
    bit<8>    key;
}

header kvp_res_t {
    bit<8>    key;
    bit<8>    is_valid;
    bit<32>   value;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    kvp_req_t    kvp_req;
    kvp_res_t    kvp_res;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
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
      transition select(hdr.ipv4.protocol) {
        PROT_UDP: parse_udp;
        default: accept;
      }
    }

    state parse_udp {
      packet.extract(hdr.udp);
      transition select(hdr.udp.dstPort) {
        KVP_PORT: parse_kvp_req;
        default: parse_udp_src;
      }
    }

    state parse_udp_src {
      transition select(hdr.udp.srcPort) {
        KVP_PORT: parse_kvp_res;
        default: accept;
      }
    }

    state parse_kvp_req {
      packet.extract(hdr.kvp_req);
      transition accept;
    }

    state parse_kvp_res {
      packet.extract(hdr.kvp_res);
      transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<8>>(256) valid_keys;
    register<bit<32>>(256) reg_values;

    action drop() {
      mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
      standard_metadata.egress_spec = port;
      hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
      hdr.ethernet.dstAddr = dstAddr;
      hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action kvp_redirect(bit<32> value) {
      hdr.ipv4.totalLen = hdr.ipv4.totalLen + 1 + 4;
   
      bit<16> old_src = hdr.udp.srcPort;
      hdr.udp.srcPort = 1234;
      hdr.udp.dstPort = old_src;
      hdr.udp.length = hdr.udp.length+1+4;
      hdr.udp.csum = 0;

      hdr.kvp_res.setValid();
      hdr.kvp_res.key = hdr.kvp_req.key;
      hdr.kvp_res.is_valid = 1;
      hdr.kvp_res.value = value;

      hdr.kvp_req.setInvalid();

      bit<32> ipv4_src = hdr.ipv4.srcAddr;
      hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
      hdr.ipv4.dstAddr = ipv4_src;
    }

    table ipv4_lpm {
      key = { hdr.ipv4.dstAddr: lpm; }
      actions = { ipv4_forward; drop; NoAction; }
      size = 1024;
      default_action = drop();
    }

    table kvp_sw_exact {
      key = { hdr.kvp_req.key: exact; }
      actions = { kvp_redirect; NoAction; }
      size = 256;
      default_action = NoAction();
    }

    apply { 
      if (hdr.ipv4.isValid()) {
        if (hdr.kvp_req.isValid()) {
          kvp_sw_exact.apply();

          if (hdr.kvp_req.isValid()) {
            bit<8> key_is_valid;
            valid_keys.read(key_is_valid, (bit<32>)hdr.kvp_req.key);

            if (key_is_valid == 1) {
              bit<32> key_value;
              reg_values.read(key_value, (bit<32>)hdr.kvp_req.key);
              kvp_redirect(key_value);
            }
          }
        }
        else if (hdr.kvp_res.isValid()) {
          valid_keys.write((bit<32>)hdr.kvp_res.key, hdr.kvp_res.is_valid);
          reg_values.write((bit<32>)hdr.kvp_res.key, hdr.kvp_res.value);
        }

        ipv4_lpm.apply();
      }
      else {
        drop();
      }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { 
      update_checksum(
        hdr.ipv4.isValid(),
        { hdr.ipv4.version,
          hdr.ipv4.ihl,
          hdr.ipv4.diffserv,
          hdr.ipv4.totalLen,
          hdr.ipv4.identification,
          hdr.ipv4.flags,
          hdr.ipv4.fragOffset,
          hdr.ipv4.ttl,
          hdr.ipv4.protocol,
          hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr },
        hdr.ipv4.hdrChecksum,
        HashAlgorithm.csum16
      );
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
      packet.emit(hdr.ethernet);
      packet.emit(hdr.ipv4);
      packet.emit(hdr.udp);
      packet.emit(hdr.kvp_req);
      packet.emit(hdr.kvp_res);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
