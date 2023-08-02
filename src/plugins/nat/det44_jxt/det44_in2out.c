/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 * @brief Deterministic NAT (CGN) inside to outside translation
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <nat/det44/det44.h>
#include <nat/det44/det44_inlines.h>

#include <nat/lib/lib.h>
#include <nat/lib/inlines.h>
#include <nat/lib/nat_inlines.h>

typedef enum // 枚举类型, 表示不同的下一步处理方式
{
  DET44_IN2OUT_NEXT_LOOKUP, // 表示需要进行下一步的查找操作。
  DET44_IN2OUT_NEXT_DROP,   // 表示需要丢弃该数据包
  DET44_IN2OUT_NEXT_ICMP_ERROR, // 表示需要发送ICMP错误消息
  DET44_IN2OUT_N_NEXT,          // 表示该枚举类型的成员数量
} det44_in2out_next_t;

typedef struct       // 存储特定的跟踪信息
{
  u32 sw_if_index;   // 用于存储软件接口索引
  u32 next_index;    // 用于存储下一步处理方式的索引
  u32 session_index; // 用于存储会话索引
} det44_in2out_trace_t;

#define foreach_det44_in2out_error                 \
  _ (UNSUPPORTED_PROTOCOL, "Unsupported protocol") \
  _ (NO_TRANSLATION, "No translation")             \
  _ (BAD_ICMP_TYPE, "unsupported ICMP type")       \
  _ (OUT_OF_PORTS, "Out of ports")                 \
  _ (IN2OUT_PACKETS, "Good in2out packets processed")

typedef enum // 用于表示不同的错误类型
{
#define _(sym, str) DET44_IN2OUT_ERROR_##sym,
  foreach_det44_in2out_error
#undef _
      DET44_IN2OUT_N_ERROR,
} det44_in2out_error_t;

static char *det44_in2out_error_strings[] =
    { // 用于存储与错误枚举成员对应的字符串
#define _(sym, string) string,
        foreach_det44_in2out_error
#undef _
};

// 格式化打印(det44_in2out_trace_t)结构体的跟踪信息
static u8 *format_det44_in2out_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  det44_in2out_trace_t *t = va_arg (*args, det44_in2out_trace_t *);

  s = format (s, "DET44_IN2OUT: sw_if_index %d, next index %d, session %d",
              t->sw_if_index, t->next_index, t->session_index);

  return s;
}

#ifndef CLIB_MARCH_VARIANT
/**
 * Get address and port values to be used for ICMP packet translation
 * and create session if needed
 *
 * @param[in,out] node           NAT node runtime
 * @param[in] thread_index       thread index
 * @param[in,out] b0             buffer containing packet to be translated
 * @param[in,out] ip0            ip header
 * @param[out] p_proto           protocol used for matching
 * @param[out] p_value           address and port after NAT translation
 * @param[out] p_dont_translate  if packet should not be translated
 * @param d                      optional parameter
 * @param e                      optional parameter
 */
/*
// icmp_match_in2out_det 并不直接处理数据包，
//
而是根据数据包的内容和内部状态信息查找相应的目的地址和端口的转换规则（destination
NAT映射）
// 这个函数主要用于查找目的地址和端口的转换规则，属于数据包转换的前置处理步骤
这个函数根据传入的ICMP数据包的相关信息，查找或创建相应的det44映射和会话，
并返回转换后的地址、端口以及处理该数据包的下一步操作。
*/
u32 icmp_match_in2out_det (vlib_node_runtime_t *node, u32 thread_index,
                           vlib_buffer_t *b0, ip4_header_t *ip0,
                           ip4_address_t *addr, u16 *port, u32 *fib_index,
                           nat_protocol_t *proto, void *d, void *e,
                           u8 *dont_translate)
{
  det44_main_t *dm = &det44_main;     // 用于存储det44的主要配置信息
  vlib_main_t *vm = vlib_get_main (); // 用于获取当前时间等操作
  icmp46_header_t *icmp0;             // 用于指向ICMP头部
  u32 sw_if_index0;                   // 用于存储接口索引
  u32 rx_fib_index0; // 用于存储输入数据包所属的FIB表索引
  nat_protocol_t protocol;
  snat_det_out_key_t key0;
  u32 next0 = ~0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  snat_det_map_t *mp0 = 0;
  ip4_address_t new_addr0;
  u16 lo_port0, i0;
  snat_det_session_t *ses0 = 0;
  ip4_address_t in_addr;
  u16 in_port;
  *dont_translate = 0;

  icmp0 = (icmp46_header_t *)ip4_next_header (ip0); // 获取指向IPv4
                                                    // ICMP头的指针icmp0
  echo0 = (icmp_echo_header_t *)(icmp0 + 1);
  sw_if_index0 =
      vnet_buffer (b0)->sw_if_index[VLIB_RX]; // 获取接收数据包的软件接口索引。
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (
      sw_if_index0); // 获取接收数据包的入接口FIB索引

  if (!icmp_type_is_error_message (
          vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
    {
      protocol = NAT_PROTOCOL_ICMP;
      in_addr = ip0->src_address;
      in_port = vnet_buffer (b0)->ip.reass.l4_src_port;
    }
  else
    {
      /* if error message, then it's not fragmented and we can access it */
      inner_ip0 = (ip4_header_t *)(echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      protocol = ip_proto_to_nat_proto (inner_ip0->protocol);
      in_addr = inner_ip0->dst_address;
      switch (protocol)
        {
        case NAT_PROTOCOL_ICMP:
          inner_icmp0 = (icmp46_header_t *)l4_header;
          inner_echo0 = (icmp_echo_header_t *)(inner_icmp0 + 1);
          in_port = inner_echo0->identifier;
          break;
        case NAT_PROTOCOL_UDP:
        case NAT_PROTOCOL_TCP:
          in_port = ((tcp_udp_header_t *)l4_header)->dst_port;
          break;
        default:
          b0->error = node->errors[DET44_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
          next0 = DET44_IN2OUT_NEXT_DROP;
          goto out;
        }
    }

  mp0 = snat_det_map_by_user (
      &in_addr); // 通过in_addr（目的IPv4地址）查找对应的destination
                 // NAT映射
  if (PREDICT_FALSE (!mp0)) // 如果没找到
    {
      if (PREDICT_FALSE (det44_translate (node, sw_if_index0, ip0,
                                          IP_PROTOCOL_ICMP, rx_fib_index0)))
        {
          *dont_translate = 1;
          goto out;
        }
      next0 = DET44_IN2OUT_NEXT_DROP;
      b0->error = node->errors[DET44_IN2OUT_ERROR_NO_TRANSLATION];
      goto out;
    }

  snat_det_forward (mp0, &in_addr, &new_addr0,
                    &lo_port0); // 进行目的地址和端口的NAT转换

  key0.ext_host_addr = ip0->dst_address;
  key0.ext_host_port = 0;

  ses0 = snat_det_find_ses_by_in (mp0, &in_addr, in_port, key0);
  if (PREDICT_FALSE (!ses0))
    {
      if (PREDICT_FALSE (det44_translate (node, sw_if_index0, ip0,
                                          IP_PROTOCOL_ICMP, rx_fib_index0)))
        {
          *dont_translate = 1;
          goto out;
        }
      if (icmp0->type != ICMP4_echo_request)
        {
          b0->error = node->errors[DET44_IN2OUT_ERROR_BAD_ICMP_TYPE];
          next0 = DET44_IN2OUT_NEXT_DROP;
          goto out;
        }
      for (i0 = 0; i0 < mp0->ports_per_host; i0++)
        {
          key0.out_port = clib_host_to_net_u16 (
              lo_port0 + ((i0 + clib_net_to_host_u16 (echo0->identifier)) %
                          mp0->ports_per_host));

          if (snat_det_get_ses_by_out (mp0, &in_addr, key0.as_u64))
            continue;

          ses0 = snat_det_ses_create (thread_index, mp0, &in_addr,
                                      echo0->identifier, &key0);
          break;
        }
      if (PREDICT_FALSE (!ses0))
        {
          next0 = DET44_IN2OUT_NEXT_DROP;
          b0->error = node->errors[DET44_IN2OUT_ERROR_OUT_OF_PORTS];
          goto out;
        }
    }

  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
                         ICMP4_echo_request &&
                     !icmp_type_is_error_message (
                         vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags)))
    {
      b0->error = node->errors[DET44_IN2OUT_ERROR_BAD_ICMP_TYPE];
      next0 = DET44_IN2OUT_NEXT_DROP;
      goto out;
    }

  u32 now = (u32)vlib_time_now (vm);

  ses0->state = DET44_SESSION_ICMP_ACTIVE;
  ses0->expire = now + dm->timeouts.icmp;

out:
  *proto = protocol;
  if (ses0)
    {
      *addr = new_addr0;
      *fib_index = dm->outside_fib_index;
      *port = ses0->out.out_port;
    }
  if (d)
    *(snat_det_session_t **)d = ses0;
  if (e)
    *(snat_det_map_t **)e = mp0;
  return next0;
}
#endif

// icmp_match_in2out_det 函数是用于查找 ICMP 数据包的目的地址和端口的转换规则
// det44_icmp_in2out
// 函数则是用于具体的数据包处理和转换,是处理具体数据包的逻辑实现，属于数据包转换的核心部分。
// 它接收从内部网络传入的 ICMP 数据包，并对其进行转换，使其源 IPv4
// 地址和端口从内部网络转换为外部网络对应的地址和端口。
#ifndef CLIB_MARCH_VARIANT
u32 det44_icmp_in2out (vlib_buffer_t *b0, ip4_header_t *ip0,
                       icmp46_header_t *icmp0, u32 sw_if_index0,
                       u32 rx_fib_index0, vlib_node_runtime_t *node, u32 next0,
                       u32 thread_index, void *d, void *e)
{
  vlib_main_t *vm = vlib_get_main ();
  u16 old_id0, new_id0, port, checksum0, old_checksum0, new_checksum0;
  u32 new_addr0, old_addr0, next0_tmp, fib_index;
  icmp_echo_header_t *echo0, *inner_echo0;
  icmp46_header_t *inner_icmp0;
  ip4_header_t *inner_ip0;
  ip4_address_t addr;
  void *l4_header;
  u8 dont_translate;
  ip_csum_t sum0;
  nat_protocol_t protocol;

  echo0 = (icmp_echo_header_t *)(icmp0 + 1);
  next0_tmp =
      icmp_match_in2out_det (node, thread_index, b0, ip0, &addr, &port,
                             &fib_index, &protocol, d, e, &dont_translate);
  if (next0_tmp != ~0)
    next0 = next0_tmp;
  if (next0 == DET44_IN2OUT_NEXT_DROP || dont_translate)
    goto out;

  if (PREDICT_TRUE (!ip4_is_fragment (ip0)))
    {
      sum0 = ip_incremental_checksum_buffer (
          vm, b0, (u8 *)icmp0 - (u8 *)vlib_buffer_get_current (b0),
          ntohs (ip0->length) - ip4_header_bytes (ip0), 0);
      checksum0 = ~ip_csum_fold (sum0);
      if (PREDICT_FALSE (checksum0 != 0 && checksum0 != 0xffff))
        {
          next0 = DET44_IN2OUT_NEXT_DROP;
          goto out;
        }
    }

  old_addr0 = ip0->src_address.as_u32;
  new_addr0 = ip0->src_address.as_u32 = addr.as_u32;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                         src_address /* changed member */);
  ip0->checksum = ip_csum_fold (sum0);

  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
    {
      if (icmp0->checksum == 0)
        icmp0->checksum = 0xffff;

      if (!icmp_type_is_error_message (icmp0->type))
        {
          new_id0 = port;
          if (PREDICT_FALSE (new_id0 != echo0->identifier))
            {
              old_id0 = echo0->identifier;
              new_id0 = port;
              echo0->identifier = new_id0;

              sum0 = icmp0->checksum;
              sum0 = ip_csum_update (sum0, old_id0, new_id0,
                                     icmp_echo_header_t, identifier);
              icmp0->checksum = ip_csum_fold (sum0);
            }
        }
      else
        {
          inner_ip0 = (ip4_header_t *)(echo0 + 1);
          l4_header = ip4_next_header (inner_ip0);

          if (!ip4_header_checksum_is_valid (inner_ip0))
            {
              next0 = DET44_IN2OUT_NEXT_DROP;
              goto out;
            }

          /* update inner destination IP address */
          old_addr0 = inner_ip0->dst_address.as_u32;
          inner_ip0->dst_address = addr;
          new_addr0 = inner_ip0->dst_address.as_u32;
          sum0 = icmp0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                                 dst_address /* changed member */);
          icmp0->checksum = ip_csum_fold (sum0);

          /* update inner IP header checksum */
          old_checksum0 = inner_ip0->checksum;
          sum0 = inner_ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                                 dst_address /* changed member */);
          inner_ip0->checksum = ip_csum_fold (sum0);
          new_checksum0 = inner_ip0->checksum;
          sum0 = icmp0->checksum;
          sum0 = ip_csum_update (sum0, old_checksum0, new_checksum0,
                                 ip4_header_t, checksum);
          icmp0->checksum = ip_csum_fold (sum0);

          switch (protocol)
            {
            case NAT_PROTOCOL_ICMP:
              inner_icmp0 = (icmp46_header_t *)l4_header;
              inner_echo0 = (icmp_echo_header_t *)(inner_icmp0 + 1);

              old_id0 = inner_echo0->identifier;
              new_id0 = port;
              inner_echo0->identifier = new_id0;

              sum0 = icmp0->checksum;
              sum0 = ip_csum_update (sum0, old_id0, new_id0,
                                     icmp_echo_header_t, identifier);
              icmp0->checksum = ip_csum_fold (sum0);
              break;
            case NAT_PROTOCOL_UDP:
            case NAT_PROTOCOL_TCP:
              old_id0 = ((tcp_udp_header_t *)l4_header)->dst_port;
              new_id0 = port;
              ((tcp_udp_header_t *)l4_header)->dst_port = new_id0;

              sum0 = icmp0->checksum;
              sum0 = ip_csum_update (sum0, old_id0, new_id0, tcp_udp_header_t,
                                     dst_port);
              icmp0->checksum = ip_csum_fold (sum0);
              break;
            default:
              ASSERT (0);
            }
        }
    }

  if (vnet_buffer (b0)->sw_if_index[VLIB_TX] == ~0)
    vnet_buffer (b0)->sw_if_index[VLIB_TX] = fib_index;
out:
  return next0;
}
#endif

/*******************************************************/
/*********************** my modify begin *******************/

// 假设有两个外部端口范围
#define PORT_RANGE_1_START 1024
#define PORT_RANGE_1_END 3071
#define PORT_RANGE_2_START 3072
#define PORT_RANGE_2_END 5119
#define PORT_RANGE_SIZE 2048

/******************** my modify end *************************/
/***********************************************************/

VLIB_NODE_FN (det44_in2out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node,
 vlib_frame_t *frame) // frame: 包含从前一个节点传递的数据包信息的帧结构指针。
{
  u32 n_left_from, *from;
  u32 pkts_processed = 0;
  det44_main_t *dm = &det44_main;
  u32 now = (u32)vlib_time_now (vm);
  u32 thread_index =
      vm->thread_index; // 获取当前线程的索引，用于多线程环境下的数据包处理。

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors; // frame中数据包的数量

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE],
      **b = bufs; // 定义缓冲区指针数组用于存储数据包的缓冲区指针。
  u16 nexts[VLIB_FRAME_SIZE],
      *next = nexts; // 定义下一跳数组用于存储数据包的下一跳索引。
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from > 0) // 最后剩下一个，就处理一个
    {
      vlib_buffer_t *b0;  // 指向当前正在处理的数据包的缓冲区
      u32 next0;
      u32 sw_if_index0;
      ip4_header_t *ip0;
      ip_csum_t sum0;
      ip4_address_t new_addr0, old_addr0;
      u16 old_port0, new_port0, lo_port0, i0;
      udp_header_t *udp0;
      tcp_header_t *tcp0;
      u32 proto0;
      snat_det_out_key_t key0;
      snat_det_session_t *ses0 = 0;
      u32 rx_fib_index0;
      icmp46_header_t *icmp0;

      b0 = *b;
      b++;
      // 当前数据包处理完成后的下一步操作，初始值为DET44_IN2OUT_NEXT_LOOKUP。
      next0 = DET44_IN2OUT_NEXT_LOOKUP;

      ip0 = vlib_buffer_get_current (b0);
      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *)udp0;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      /*******************************************************/
      /*********************** my modify begin *******************/
      // 生成映射表
      // dm->det_maps[0]->in_addr.as_u32 = 192.168.1.0   10.2.1.0
      // dm->det_maps[1]->in_addr.as_u32 = 192.168.2.0   10.2.2.0
      // ...
      // dm->det_maps[64]->in_addr.as_u32 = 192.168.64.0   10.2.64.0
      ip4_address_t in_addr, out_addr;
      for (int i = 0; i < MY_MAX_DET_MAPS; ++i)
        {
          dm->det_maps[i].in_plan = MY_PLEN;
          dm->det_maps[i].out_plan = MY_PLEN;
          // 192.168.1.0
          dm->det_maps[i].in_addr.as_u32 = clib_host_to_net_u32 (0xC0A80100) +
                                           clib_host_to_net_u32 (i << 8);
          // 10.2.1.0
          dm->det_maps[i].out_addr.as_u32 = clib_host_to_net_u32 (0x0A020100) +
                                            clib_host_to_net_u32 (i << 8);
        }

      // 创建哈希表
      clib_bihash_8_8_init (&dm->translation_table, "det44_translation_table",
                            MY_MAX_DET_MAPS, 0);
      // 初始化哈希表
      for (int i = 0; i < MY_MAX_DET_MAPS; i++)
        {
          // 将每个映射表中的in_addr作为键，映射表的索引作为值，插入哈希表
          clib_bihash_kv_8_8_t kv;
          kv.key[0] = dm->det_maps[i].in_addr.as_u32;
          kv.key[1] = 0;
          kv.value = i;
          clib_bihash_add_del_8_8 (&det44_main.translation_table, &kv, 1);
        }

      /******************** my modify end *************************/
      /***********************************************************/

      // 检查IPv4数据包的TTL（Time To Live）字段是否为1
      if (PREDICT_FALSE (ip0->ttl == 1))
        {
          vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;
          icmp4_error_set_vnet_buffer (
              b0, ICMP4_time_exceeded,
              ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
          next0 = DET44_IN2OUT_NEXT_ICMP_ERROR;
          goto trace00;
        }

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      // 如果是 icmp ，交给det44_icmp_in2out 函数处理
      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
        {
          rx_fib_index0 =
              ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
          icmp0 = (icmp46_header_t *)udp0;

          next0 =
              det44_icmp_in2out (b0, ip0, icmp0, sw_if_index0, rx_fib_index0,
                                 node, next0, thread_index, &ses0, &mp0);
          goto trace00;
        }

      /***********************************************************/
      /*********************** my modify begin *******************/
      // 根据 源ip地址 查找映射表
      clib_bihash_kv_8_8_t kv;
      kv.key[0] = ip0->src_address.as_u32 & ip4_main.fib_masks[MY_PLEN];
      kv.key[1] = 0; // IPv4地址，kv.key[1]应为0
      clib_bihash_search_8_8 (&det44_main.translation_table, &kv);
      if (PREDICT_FALSE (kv.value >= MY_MAX_DET_MAPS))
        {
          // 没找到对应的映射表，处理错误逻辑
          det44_log_info ("no match mapping for internal host ip %U",
                          format_ip4_address, &ip0->src_address);
          next0 = DET44_IN2OUT_NEXT_DROP;
          b0->error = node->errors[DET44_IN2OUT_ERROR_NO_TRANSLATION];
          goto trace00;
        }

      snat_det_map_t *mp0 = dm->det_maps[kv.value];

      // 查找映射的外部地址相应的会话表
      // 计算偏移量
      // ip0->src_address.as_u8 为 192.168.10.0 - 192.168.10.127
      u32 addr_offset = (ip0->src_address.as_u8[3] / 2);
      if (addr_offset >= 64)
        {
          det44_log_info ("invalid internal host ip %U", format_ip4_address,
                          &ip0->src_address);
          next0 = DET44_IN2OUT_NEXT_DROP;
          b0->error = node->errors[DET44_IN2OUT_ERROR_NO_TRANSLATION];
          goto trace00;
        }

      snat_det_session_table_t *table0 = mp0->sessions_tables[addr_offset];

      // 将外部起始地址与偏移量相加得到映射到的外部地址
      ip4_address_t mapped_addr;
      mapped_addr.as_u32 = clib_host_to_net_u32 (
          clib_net_to_host_u32 (mp0->out_addr.as_u32) + addr_offset);
      // 是这个外部地址下的第一段或第二段端口范围
      u32 port_range_index = (ip0->src_address.as_u8[3] % 2);
      u16 port_range_start, port_range_end;
      if (port_range_index == 0)
        {
          port_range_start = PORT_RANGE_1_START;
          port_range_end = PORT_RANGE_1_END;
        }
      else
        {
          port_range_start = PORT_RANGE_2_START;
          port_range_end = PORT_RANGE_2_END;
        }

      // 计算要映射的外部端口，临时端口
      u16 mapped_port = port_range_start;

      // 根据源ip，目标ip和端口查找会话
      key0.ext_host_addr = ip0->dst_address; // 目标ip地址
      key0.ext_host_port = tcp0->dst;        // 目标端口

      // 找到映射的外部地址对应的会话表
      {
        for (i0 = 0; i0 < MY_SESSIONS_PER_EXTERNAL_ADDR / 2; i0++)
        {
          snat_det_session_t *ses0 = table0->sessions[i0 + mapped_port];
          if (s0->expire <= now)
            {
              continue; // 跳过已超时的会话
            }
          if (s0->in_port == udp0->src_port &&
              s0->out.ext_host_addr.as_u32 == mapped_addr.as_u32 &&
              s0->out.ext_host_port == mapped_port)
            {
              goto done;
            }
        }
        ses0 = 0;
      }
      done:



      /******************** my modify end *************************/
      /***********************************************************/

      // 没找到，则创建会话
      if (PREDICT_FALSE (!ses0))
        {
          // 循环会尝试不同的目标端口，直到找到一个可用的目标端口
          for (i0 = 0; i0 < MY_SESSIONS_PER_EXTERNAL_ADDR / 2; i0++)
            {
              snat_det_session_t *s0 = table0->sessions[i0 + mapped_port];

              // 表示这个端口还没被用过
              if (s0->in_port == 0)
                {
                  if (clib_atomic_bool_cmp_and_swap (&s0->in_port, 0,
                                                     udp0->src_port))
                    {
                      s0->out.ext_host_addr = mapped_addr;
                      s0->out.ext_host_port = mapped_port;
                      s0->state = DET44_SESSION_UNKNOWN;
                      s0->expire = now + dm->timeouts.tcp_transitory;
                      clib_atomic_add_fetch (&table0->ses_num, 1);
                      break;
                    }
                }
            }

          // Det44会话数量达到上限，将数据包丢弃，并发送ICMP错误报文，通知发送者无法建立新的连接
          if (PREDICT_FALSE (!ses0))
            {
              /* too many sessions for user, send ICMP error packet */
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;
              icmp4_error_set_vnet_buffer (
                  b0, ICMP4_destination_unreachable,
                  ICMP4_destination_unreachable_destination_unreachable_host,
                  0);
              next0 = DET44_IN2OUT_NEXT_ICMP_ERROR;
              goto trace00;
            }
        }
      // 如果能查到会话，则直接使用查到的会话中的地址和端口号，而不是
      // snat_det_forward 转换后的地址和端口号
      old_port0 = udp0->src_port;
      udp0->src_port = new_port0 = ses0->out.out_port;

      old_addr0.as_u32 = ip0->src_address.as_u32;
      ip0->src_address.as_u32 = new_addr0.as_u32;

      // 将数据包的输出接口设置为Det44会话中指定的外部FIB表的索引值。这是为了确保转换后的数据包能够正确地路由出去。
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = dm->outside_fib_index;

      // 重新计算校验和
      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                             ip4_header_t, src_address /* changed member */);
      ip0->checksum = ip_csum_fold (sum0);

      // 根据TCP标志和会话的状态，更新会话的状态（ses0->state）
      // 如果是TCP
      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
        {
          if (tcp0->flags & TCP_FLAG_SYN)
            ses0->state = DET44_SESSION_TCP_SYN_SENT;
          else if (tcp0->flags & TCP_FLAG_ACK &&
                   ses0->state == DET44_SESSION_TCP_SYN_SENT)
            ses0->state = DET44_SESSION_TCP_ESTABLISHED;
          else if (tcp0->flags & TCP_FLAG_FIN &&
                   ses0->state == DET44_SESSION_TCP_ESTABLISHED)
            ses0->state = DET44_SESSION_TCP_FIN_WAIT;
          else if (tcp0->flags & TCP_FLAG_ACK &&
                   ses0->state == DET44_SESSION_TCP_FIN_WAIT)
            snat_det_ses_close (mp0, ses0);
          else if (tcp0->flags & TCP_FLAG_FIN &&
                   ses0->state == DET44_SESSION_TCP_CLOSE_WAIT)
            ses0->state = DET44_SESSION_TCP_LAST_ACK;
          else if (tcp0->flags == 0 && ses0->state == DET44_SESSION_UNKNOWN)
            ses0->state = DET44_SESSION_TCP_ESTABLISHED;

          sum0 = tcp0->checksum;
          sum0 =
              ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                              ip4_header_t, dst_address /* changed member */);
          sum0 = ip_csum_update (sum0, old_port0, new_port0,
                                 ip4_header_t /* cheat */,
                                 length /* changed member */);
          mss_clamping (dm->mss_clamping, tcp0, &sum0);
          tcp0->checksum = ip_csum_fold (sum0);
        }
      else // 如果是UDP
        {
          ses0->state = DET44_SESSION_UDP_ACTIVE;

          if (PREDICT_FALSE (udp0->checksum))
            {
              sum0 = udp0->checksum;
              sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                                     ip4_header_t,
                                     dst_address /* changed member */);
              sum0 = ip_csum_update (sum0, old_port0, new_port0,
                                     ip4_header_t /* cheat */,
                                     length /* changed member */);
              udp0->checksum = ip_csum_fold (sum0);
            }
        }

      // 更新会话的过期时间
      switch (ses0->state)
        {
        case DET44_SESSION_UDP_ACTIVE:
          ses0->expire = now + dm->timeouts.udp;
          break;
        case DET44_SESSION_TCP_SYN_SENT:
        case DET44_SESSION_TCP_FIN_WAIT:
        case DET44_SESSION_TCP_CLOSE_WAIT:
        case DET44_SESSION_TCP_LAST_ACK:
          ses0->expire = now + dm->timeouts.tcp.transitory;
          break;
        case DET44_SESSION_TCP_ESTABLISHED:
          ses0->expire = now + dm->timeouts.tcp.established;
          break;
        }

    trace00:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                         (b0->flags & VLIB_BUFFER_IS_TRACED)))
        {
          det44_in2out_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
          t->sw_if_index = sw_if_index0;
          t->next_index = next0;
          t->session_index = ~0;
          if (ses0)
            t->session_index = ses0 - mp0->sessions;
        }

      pkts_processed += next0 != DET44_IN2OUT_NEXT_DROP;

      n_left_from--;
      next[0] = next0;
      next++;
    }

  // 将处理过的数据包发送到下一个节点
  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *)nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, dm->in2out_node_index,
                               DET44_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

// 用于注册一个节点函数（det44_in2out_node）
// 将 det44_in2out_node
// 这个节点函数注册为一个VPP节点，并定义了节点的一些属性，如节点名称、处理数据包的向量大小、跟踪函数等
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (det44_in2out_node) = {
    .name = "det44-in2out",
    .vector_size = sizeof (u32),
    .format_trace = format_det44_in2out_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = ARRAY_LEN (det44_in2out_error_strings),
    .error_strings = det44_in2out_error_strings,
    .runtime_data_bytes = sizeof (det44_runtime_t),
    .n_next_nodes = DET44_IN2OUT_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes =
        {
            [DET44_IN2OUT_NEXT_DROP] = "error-drop",
            [DET44_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
            [DET44_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
        },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
