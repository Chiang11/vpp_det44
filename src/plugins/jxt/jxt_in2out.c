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

#include <plugins/jxt/jxt.h>
#include <plugins/jxt/jxt_inlines.h>

#include <nat/lib/lib.h>
#include <nat/lib/inlines.h>
#include <nat/lib/nat_inlines.h>

///////////////////////////////////
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <stdlib.h>
//////////////////////////////////

typedef enum              // 枚举类型, 表示不同的下一步处理方式
{
  jxt_IN2OUT_NEXT_LOOKUP, // 表示需要进行下一步的查找操作。
  jxt_IN2OUT_NEXT_DROP,   // 表示需要丢弃该数据包
  jxt_IN2OUT_NEXT_ICMP_ERROR, // 表示需要发送ICMP错误消息
  jxt_IN2OUT_N_NEXT,          // 表示该枚举类型的成员数量
} jxt_in2out_next_t;

typedef struct       // 存储特定的跟踪信息
{
  u32 sw_if_index;   // 用于存储软件接口索引
  u32 next_index;    // 用于存储下一步处理方式的索引
  u32 session_index; // 用于存储会话索引
} jxt_in2out_trace_t;

#define foreach_jxt_in2out_error                   \
  _ (UNSUPPORTED_PROTOCOL, "Unsupported protocol") \
  _ (NO_TRANSLATION, "No translation")             \
  _ (BAD_ICMP_TYPE, "unsupported ICMP type")       \
  _ (OUT_OF_PORTS, "Out of ports")                 \
  _ (IN2OUT_PACKETS, "Good in2out packets processed")

typedef enum // 用于表示不同的错误类型
{
#define _(sym, str) jxt_IN2OUT_ERROR_##sym,
  foreach_jxt_in2out_error
#undef _
      jxt_IN2OUT_N_ERROR,
} jxt_in2out_error_t;

static char *jxt_in2out_error_strings[] =
    { // 用于存储与错误枚举成员对应的字符串
#define _(sym, string) string,
        foreach_jxt_in2out_error
#undef _
};

// 格式化打印(jxt_in2out_trace_t)结构体的跟踪信息
static u8 *format_jxt_in2out_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  jxt_in2out_trace_t *t = va_arg (*args, jxt_in2out_trace_t *);

  s = format (s, "jxt_IN2OUT: sw_if_index %d, next index %d, session %d",
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
这个函数根据传入的ICMP数据包的相关信息，查找或创建相应的jxt映射和会话，
并返回转换后的地址、端口以及处理该数据包的下一步操作。
*/
u32 icmp_match_in2out_det (vlib_node_runtime_t *node, u32 thread_index,
                           vlib_buffer_t *b0, ip4_header_t *ip0,
                           ip4_address_t *addr, u16 *port, u32 *fib_index,
                           nat_protocol_t *proto, void *d, void *e,
                           u8 *dont_translate)
{
  jxt_main_t *dm = &jxt_main;         // 用于存储jxt的主要配置信息
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
          b0->error = node->errors[jxt_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
          next0 = jxt_IN2OUT_NEXT_DROP;
          goto out;
        }
    }

  mp0 = snat_det_map_by_user (
      &in_addr); // 通过in_addr（目的IPv4地址）查找对应的destination
                 // NAT映射
  if (PREDICT_FALSE (!mp0)) // 如果没找到
    {
      if (PREDICT_FALSE (jxt_translate (node, sw_if_index0, ip0,
                                        IP_PROTOCOL_ICMP, rx_fib_index0)))
        {
          *dont_translate = 1;
          goto out;
        }
      next0 = jxt_IN2OUT_NEXT_DROP;
      b0->error = node->errors[jxt_IN2OUT_ERROR_NO_TRANSLATION];
      goto out;
    }

  snat_det_forward (mp0, &in_addr, &new_addr0,
                    &lo_port0); // 进行目的地址和端口的NAT转换

  key0.ext_host_addr = ip0->dst_address;
  key0.ext_host_port = 0;

  ses0 = snat_det_find_ses_by_in (mp0, &in_addr, in_port, key0);
  if (PREDICT_FALSE (!ses0))
    {
      if (PREDICT_FALSE (jxt_translate (node, sw_if_index0, ip0,
                                        IP_PROTOCOL_ICMP, rx_fib_index0)))
        {
          *dont_translate = 1;
          goto out;
        }
      if (icmp0->type != ICMP4_echo_request)
        {
          b0->error = node->errors[jxt_IN2OUT_ERROR_BAD_ICMP_TYPE];
          next0 = jxt_IN2OUT_NEXT_DROP;
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
          next0 = jxt_IN2OUT_NEXT_DROP;
          b0->error = node->errors[jxt_IN2OUT_ERROR_OUT_OF_PORTS];
          goto out;
        }
    }

  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
                         ICMP4_echo_request &&
                     !icmp_type_is_error_message (
                         vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags)))
    {
      b0->error = node->errors[jxt_IN2OUT_ERROR_BAD_ICMP_TYPE];
      next0 = jxt_IN2OUT_NEXT_DROP;
      goto out;
    }

  u32 now = (u32)vlib_time_now (vm);

  ses0->state = jxt_SESSION_ICMP_ACTIVE;
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
// jxt_icmp_in2out
// 函数则是用于具体的数据包处理和转换,是处理具体数据包的逻辑实现，属于数据包转换的核心部分。
// 它接收从内部网络传入的 ICMP 数据包，并对其进行转换，使其源 IPv4
// 地址和端口从内部网络转换为外部网络对应的地址和端口。
#ifndef CLIB_MARCH_VARIANT
u32 jxt_icmp_in2out (vlib_buffer_t *b0, ip4_header_t *ip0,
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
  if (next0 == jxt_IN2OUT_NEXT_DROP || dont_translate)
    goto out;

  if (PREDICT_TRUE (!ip4_is_fragment (ip0)))
    {
      sum0 = ip_incremental_checksum_buffer (
          vm, b0, (u8 *)icmp0 - (u8 *)vlib_buffer_get_current (b0),
          ntohs (ip0->length) - ip4_header_bytes (ip0), 0);
      checksum0 = ~ip_csum_fold (sum0);
      if (PREDICT_FALSE (checksum0 != 0 && checksum0 != 0xffff))
        {
          next0 = jxt_IN2OUT_NEXT_DROP;
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
              next0 = jxt_IN2OUT_NEXT_DROP;
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


// 创建会话
static_always_inline my_sess_t *
jxt_ses_create (jxt_main_t *dm, u32 thread_index, ip4_address_t *in_addr,
                u16 *last_index, u16 *ses_index, my_user_t *user0,
                u16 in_port0, u32 now)
{
  // 获取到当前要遍历的会话索引
  *ses_index = (*last_index + 1) % MY_MAX_SESS_PER_USER;
  u16 i0;
  for (i0 = 0; i0 < MY_MAX_SESS_PER_USER; i0++)
    {
      *ses_index = (*ses_index + i0) % MY_MAX_SESS_PER_USER;
      my_sess_t *ses0 = &user0->my_sess[*ses_index];
      if (ses0->in_port == 0 || ses0->expire <= now)
        {
          // 将原会话in_port对应的会话索引 置为非法值
          user0->my_sess_index_by_in[ses0->in_port] = (u16)~0;
          // 更新 my_sess[i0] 的 in_port 和 expire
          ses0->in_port = in_port0;
          ses0->out_port = *ses_index + user0->lo_port;
          ses0->state = jxt_SESSION_UNKNOWN;
          ses0->expire = now + dm->timeouts.tcp.transitory;
          *last_index = *ses_index;
          clib_atomic_add_fetch (&user0->ses_num, 1);
          return ses0;
        }
    }
  // nat_ipfix_logging_max_entries_per_user (thread_index, jxt_SES_PER_USER,
  //                                         in_addr->as_u32);
  // 没找到合适的ses
  return 0;
}

static_always_inline void jxt_ses_close (my_user_t *user0, my_sess_t *ses0)
{
  if (clib_atomic_bool_cmp_and_swap (&ses0->in_port, ses0->in_port, 0))
    {
      ses0 = 0;
      clib_atomic_add_fetch (&user0->ses_num, -1);
    }
}

VLIB_NODE_FN (jxt_in2out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node,
 vlib_frame_t *frame) // frame: 包含从前一个节点传递的数据包信息的帧结构指针。
{
  u32 n_left_from, *from;
  u32 pkts_processed = 0;
  jxt_main_t *dm = &jxt_main;
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

  /*********************** my modify begin *******************/
  snat_det_map_t *mp0;
  my_user_t *user0 = (my_user_t *)malloc(sizeof(my_user_t));
  user0->in_addr.as_u32 = 0;
  my_sess_t *ses0 = 0;
  /******************** my modify end *************************/

  while (n_left_from > 0) // 最后剩下一个，就处理一个
    {
      vlib_buffer_t *b0;  // 指向当前正在处理的数据包的缓冲区
      u32 next0;
      u32 sw_if_index0;
      ip4_header_t *ip0;
      ip_csum_t sum0;

      udp_header_t *udp0;
      tcp_header_t *tcp0;
      u32 proto0;
      // snat_det_out_key_t key0;

      u32 rx_fib_index0;
      icmp46_header_t *icmp0;

      b0 = *b;
      b++;
      // 当前数据包处理完成后的下一步操作，初始值为jxt_IN2OUT_NEXT_LOOKUP。
      next0 = jxt_IN2OUT_NEXT_LOOKUP;

      ip0 = vlib_buffer_get_current (b0);
      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *)udp0;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      /*********************** my modify begin *******************/
      ip4_address_t new_addr0 = {0}, old_addr0;
      u16 old_port0, new_port0, in_port0, ses_index, user_index, i0;
      /******************** my modify end *************************/

      // 检查IPv4数据包的TTL（Time To Live）字段是否为1
      if (PREDICT_FALSE (ip0->ttl == 1))
        {
          vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;
          icmp4_error_set_vnet_buffer (
              b0, ICMP4_time_exceeded,
              ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
          next0 = jxt_IN2OUT_NEXT_ICMP_ERROR;
          goto trace00;
        }

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      // 如果是 icmp ，交给jxt_icmp_in2out 函数处理
      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
        {
          rx_fib_index0 =
              ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
          icmp0 = (icmp46_header_t *)udp0;

          next0 = jxt_icmp_in2out (b0, ip0, icmp0, sw_if_index0, rx_fib_index0,
                                   node, next0, thread_index, &ses0, &mp0);
          goto trace00;
        }

      /***********************************************************/
      /*********************** my modify begin *******************/
      // 根据 in_addr 查找映射表
      clib_bihash_kv_8_8_t kv;
      clib_bihash_kv_8_8_t value;
      kv.key = (u64)ip0->src_address.as_u32 << 32;
      kv.value = 0;
      value.key = 0;
      value.value = 0;
      int rv = clib_bihash_search_8_8 (&dm->in_hash_table, &kv, &value);
      // if (rv == 0) {
      //     // 键存在于哈希表中，输出键值对的内容
      //     vlib_cli_output (vm, "键: %llu, 值: %u\n", kv.key, value.value);
      // } else {
      //     // 键不存在于哈希表中，输出未找到的信息
      //     vlib_cli_output (vm, "未找到键: %llu\n", kv.key);
      // }


      // 查找失败，说明是新 in_addr ，添加哈希：
      // 从上一次创建的用户索引开始遍历，last_user_index，
      // 遍历用户数据结构my_user，找到一个 ses_num = 0 的my_user填入in_addr。
      if (PREDICT_FALSE (rv != 0))
      {
        // 查找失败
        user_index = (dm->last_user_index + 1) % MY_USERS;
        for (i0 = 0; i0 < MY_USERS; i0++)
        {
          user_index = (user_index + i0) % MY_USERS;
          user0 = &dm->my_users[user_index];
          if (user0->in_addr.as_u32 == 0 || user0->ses_num == 0)
          {
            // 找到一个空in_addr的 user，或者没有会话存在的user

            // 添加哈希之前检查是否还能添加
            if(dm->in_hash_items_num < MY_USERS)
            {
              // 添加in哈希
              kv.key = (u64)ip0->src_address.as_u32 << 32;
              kv.value = user_index;
              clib_bihash_add_del_8_8 (&dm->in_hash_table, &kv, 1);
              // 哈希表条目数量加一
              clib_atomic_add_fetch (&dm->in_hash_items_num, 1);
            }
            else // 哈希表已满，删除找到的合适的用户原本in_addr对应的哈希
            {
              // 原本用户结构中存的 旧in_addr
              kv.key = (u64)user0->in_addr.as_u32 << 32;
              kv.value = user_index;
              clib_bihash_add_del_8_8 (&dm->in_hash_table, &kv, 0);

              // 添加新in_addr对应的哈希
              kv.key = (u64)ip0->src_address.as_u32 << 32;
              kv.value = user_index;
              clib_bihash_add_del_8_8 (&dm->in_hash_table, &kv, 1);
            }
            // 初始化成员
            user0->in_addr = ip0->src_address;
            user0->ses_num = 0;
            // 更新 上一次创建用户的索引
            dm->last_user_index = user_index; 
            break;
          }
          else 
          {
            // 该用户的in_addr正在被使用且还有会话，则遍历下一个
            continue;
          }
        }
        // 判断：没找到则报错
        if(PREDICT_FALSE(user0 -> in_addr.as_u32 == 0))
        {
          jxt_log_info ("has reached the maximum number of users, internal host ip: %U",
          format_ip4_address, &ip0->src_address);
          next0 = jxt_IN2OUT_NEXT_DROP;
          b0->error = node->errors[jxt_IN2OUT_ERROR_NO_TRANSLATION];
          goto trace00;
        }
      }
      else // 哈希表查找成功
      {
        // 拿到该 in_addr 的数据结构
        user_index = value.value;
        user0 = &dm->my_users[user_index];
      }

      new_addr0 = user0->out_addr;
      in_port0 = udp0->src_port;
      // ses_index 合法范围为 0 - 2047
      // 初始值为65535
      ses_index = user0->my_sess_index_by_in[in_port0];

      // 索引合法，即0 - 2047之间
      if (PREDICT_TRUE (ses_index != (u16)~0))
        {
          ses0 = &user0->my_sess[ses_index];

          // 会话未使用或会话超时，直接 创建新的会话
          if (ses0->in_port == 0 || ses0->expire <= now)
            {
              user0->last_ses_index = ses_index - 1;
              ses0 = jxt_ses_create (dm, thread_index, &ip0->src_address,
                                     &user0->last_ses_index, &ses_index, user0, in_port0, now);
            }
          else
            {
              if (ses0->in_port != in_port0)
                {
                  // 会话被其他端口占用，且未超时
                  // 遍历下一个会话，直到找到一个会话未使用或超时，创建会话
                  ses0 = jxt_ses_create (dm, thread_index, &ip0->src_address,
                                         &user0->last_ses_index, &ses_index, user0,
                                         in_port0, now);
                }
              else
              {
                // 端口相等，且未超时，不作其他操作
                goto done;
              }
            }
        }
      // 索引不合法
      else
        {
          // 遍历下一个会话，直到找到一个会话未使用或超时，创建会话
          ses0 = jxt_ses_create (dm, thread_index, &ip0->src_address,
                                 &user0->last_ses_index, &ses_index, user0, in_port0, now);
        }
      // 
      done:
        // 更新这个 in_addr 下这个in_port查到的会话索引值 
        user0->my_sess_index_by_in[in_port0] = ses_index;



      // jxt会话数量达到上限，将数据包丢弃，并发送ICMP错误报文，通知发送者无法建立新的连接
      if (PREDICT_FALSE (!ses0))
        {
          /* too many sessions for user, send ICMP error packet */
          vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;
          icmp4_error_set_vnet_buffer (
              b0, ICMP4_destination_unreachable,
              ICMP4_destination_unreachable_destination_unreachable_host, 0);
          next0 = jxt_IN2OUT_NEXT_ICMP_ERROR;
          goto trace00;
        }

      // 若找到，更新out_port
      new_port0 = user0->lo_port + ses_index;
      
      // 如果能查到会话，则直接使用查到的会话中的地址和端口号，而不是
      // snat_det_forward 转换后的地址和端口号
      old_port0 = udp0->src_port;
      udp0->src_port = new_port0;

      old_addr0.as_u32 = ip0->src_address.as_u32;
      ip0->src_address.as_u32 = new_addr0.as_u32;

      //  vlib_cli_output (vm, "sessions tables index: %d, in %U/%d out %U/%d
      //  dst %U/%d\n", value.value, format_ip4_address,
      //     &old_addr0, old_port0, format_ip4_address, &new_addr0, new_port0,
      //     format_ip4_address, &ip0->dst_address, tcp0->dst);

      // 将数据包的输出接口设置为jxt会话中指定的外部FIB表的索引值。这是为了确保转换后的数据包能够正确地路由出去。
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
            ses0->state = jxt_SESSION_TCP_SYN_SENT;
          else if (tcp0->flags & TCP_FLAG_ACK &&
                   ses0->state == jxt_SESSION_TCP_SYN_SENT)
            ses0->state = jxt_SESSION_TCP_ESTABLISHED;
          else if (tcp0->flags & TCP_FLAG_FIN &&
                   ses0->state == jxt_SESSION_TCP_ESTABLISHED)
            ses0->state = jxt_SESSION_TCP_FIN_WAIT;
          else if (tcp0->flags & TCP_FLAG_ACK &&
                   ses0->state == jxt_SESSION_TCP_FIN_WAIT)
            jxt_ses_close (user0, ses0);
          else if (tcp0->flags & TCP_FLAG_FIN &&
                   ses0->state == jxt_SESSION_TCP_CLOSE_WAIT)
            ses0->state = jxt_SESSION_TCP_LAST_ACK;
          else if (tcp0->flags == 0 && ses0->state == jxt_SESSION_UNKNOWN)
            ses0->state = jxt_SESSION_TCP_ESTABLISHED;


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
          ses0->state = jxt_SESSION_UDP_ACTIVE;

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
        case jxt_SESSION_UDP_ACTIVE:
          ses0->expire = now + dm->timeouts.udp;
          break;
        case jxt_SESSION_TCP_SYN_SENT:
        case jxt_SESSION_TCP_FIN_WAIT:
        case jxt_SESSION_TCP_CLOSE_WAIT:
        case jxt_SESSION_TCP_LAST_ACK:
          ses0->expire = now + dm->timeouts.tcp.transitory;
          break;
        case jxt_SESSION_TCP_ESTABLISHED:
          ses0->expire = now + dm->timeouts.tcp.established;
          break;
        }

    trace00:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                         (b0->flags & VLIB_BUFFER_IS_TRACED)))
        {
          jxt_in2out_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
          t->sw_if_index = sw_if_index0;
          t->next_index = next0;
          t->session_index = ~0;
          if (ses0)
            t->session_index = ses_index;
        }

      pkts_processed += next0 != jxt_IN2OUT_NEXT_DROP;

      n_left_from--;
      next[0] = next0;
      next++;
    }

  // 将处理过的数据包发送到下一个节点
  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *)nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, dm->in2out_node_index,
                               jxt_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

// 用于注册一个节点函数（jxt_in2out_node）
// 将 jxt_in2out_node
// 这个节点函数注册为一个VPP节点，并定义了节点的一些属性，如节点名称、处理数据包的向量大小、跟踪函数等
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (jxt_in2out_node) = {
    .name = "jxt-in2out",
    .vector_size = sizeof (u32),
    .format_trace = format_jxt_in2out_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = ARRAY_LEN (jxt_in2out_error_strings),
    .error_strings = jxt_in2out_error_strings,
    .runtime_data_bytes = sizeof (jxt_runtime_t),
    .n_next_nodes = jxt_IN2OUT_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes =
        {
            [jxt_IN2OUT_NEXT_DROP] = "error-drop",
            [jxt_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
            [jxt_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
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
