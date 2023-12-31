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
 * @brief Deterministic NAT (CGN) outside to inside translation
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

typedef enum
{
  DET44_OUT2IN_NEXT_DROP,
  DET44_OUT2IN_NEXT_LOOKUP,
  DET44_OUT2IN_NEXT_ICMP_ERROR,
  DET44_OUT2IN_N_NEXT,
} det44_out2in_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
} det44_out2in_trace_t;

#define foreach_det44_out2in_error                 \
  _ (UNSUPPORTED_PROTOCOL, "Unsupported protocol") \
  _ (NO_TRANSLATION, "No translation")             \
  _ (BAD_ICMP_TYPE, "unsupported ICMP type")       \
  _ (OUT2IN_PACKETS, "Good out2in packets processed")

typedef enum
{
#define _(sym, str) DET44_OUT2IN_ERROR_##sym,
  foreach_det44_out2in_error
#undef _
      DET44_OUT2IN_N_ERROR,
} det44_out2in_error_t;

static char *det44_out2in_error_strings[] = {
#define _(sym, string) string,
    foreach_det44_out2in_error
#undef _
};

static u8 *format_det44_out2in_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  det44_out2in_trace_t *t = va_arg (*args, det44_out2in_trace_t *);

  s = format (s,
              "DET44_OUT2IN: sw_if_index %d, next index %d, session index %d",
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
u32 icmp_match_out2in_det (vlib_node_runtime_t *node, u32 thread_index,
                           vlib_buffer_t *b0, ip4_header_t *ip0,
                           ip4_address_t *addr, u16 *port, u32 *fib_index,
                           nat_protocol_t *proto, void *d, void *e,
                           u8 *dont_translate)
{
  det44_main_t *dm = &det44_main;
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u8 protocol;
  snat_det_out_key_t key0;
  u32 next0 = ~0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  snat_det_map_t *mp0 = 0;
  ip4_address_t new_addr0 = {{0}};
  snat_det_session_t *ses0 = 0;
  ip4_address_t out_addr;
  *dont_translate = 0;

  icmp0 = (icmp46_header_t *)ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *)(icmp0 + 1);
  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

  if (!icmp_type_is_error_message (
          vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
    {
      protocol = NAT_PROTOCOL_ICMP;
      key0.ext_host_addr = ip0->src_address;
      key0.ext_host_port = 0;
      key0.out_port = vnet_buffer (b0)->ip.reass.l4_src_port;
      out_addr = ip0->dst_address;
    }
  else
    {
      /* if error message, then it's not fragmented and we can access it */
      inner_ip0 = (ip4_header_t *)(echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      protocol = ip_proto_to_nat_proto (inner_ip0->protocol);
      key0.ext_host_addr = inner_ip0->dst_address;
      out_addr = inner_ip0->src_address;
      switch (protocol)
        {
        case NAT_PROTOCOL_ICMP:
          inner_icmp0 = (icmp46_header_t *)l4_header;
          inner_echo0 = (icmp_echo_header_t *)(inner_icmp0 + 1);
          key0.ext_host_port = 0;
          key0.out_port = inner_echo0->identifier;
          break;
        case NAT_PROTOCOL_UDP:
        case NAT_PROTOCOL_TCP:
          key0.ext_host_port = ((tcp_udp_header_t *)l4_header)->dst_port;
          key0.out_port = ((tcp_udp_header_t *)l4_header)->src_port;
          break;
        default:
          b0->error = node->errors[DET44_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL];
          next0 = DET44_OUT2IN_NEXT_DROP;
          goto out;
        }
    }

  mp0 = snat_det_map_by_out (&out_addr);
  if (PREDICT_FALSE (!mp0))
    {
      /* Don't NAT packet aimed at the intfc address */
      if (PREDICT_FALSE (!det44_is_interface_addr (node, sw_if_index0,
                                                   ip0->dst_address.as_u32)))
        {
          *dont_translate = 1;
          goto out;
        }
      det44_log_info ("unknown dst address:  %U", format_ip4_address,
                      &ip0->dst_address);
      goto out;
    }

  snat_det_reverse (mp0, &ip0->dst_address,
                    clib_net_to_host_u16 (key0.out_port), &new_addr0);

  ses0 = snat_det_get_ses_by_out (mp0, &new_addr0, key0.as_u64);
  if (PREDICT_FALSE (!ses0))
    {
      /* Don't NAT packet aimed at the intfc address */
      if (PREDICT_FALSE (!det44_is_interface_addr (node, sw_if_index0,
                                                   ip0->dst_address.as_u32)))
        {
          *dont_translate = 1;
          goto out;
        }
      det44_log_info (
          "no match src %U:%d dst %U:%d for user %U", format_ip4_address,
          &key0.ext_host_addr, clib_net_to_host_u16 (key0.ext_host_port),
          format_ip4_address, &out_addr, clib_net_to_host_u16 (key0.out_port),
          format_ip4_address, &new_addr0);
      b0->error = node->errors[DET44_OUT2IN_ERROR_NO_TRANSLATION];
      next0 = DET44_OUT2IN_NEXT_DROP;
      goto out;
    }

  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
                         ICMP4_echo_reply &&
                     !icmp_type_is_error_message (
                         vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags)))
    {
      b0->error = node->errors[DET44_OUT2IN_ERROR_BAD_ICMP_TYPE];
      next0 = DET44_OUT2IN_NEXT_DROP;
      goto out;
    }

  goto out;

out:
  *proto = protocol;
  if (ses0)
    {
      *addr = new_addr0;
      *fib_index = dm->inside_fib_index;
      *port = ses0->in_port;
    }
  if (d)
    *(snat_det_session_t **)d = ses0;
  if (e)
    *(snat_det_map_t **)e = mp0;
  return next0;
}
#endif

#ifndef CLIB_MARCH_VARIANT
u32 det44_icmp_out2in (vlib_buffer_t *b0, ip4_header_t *ip0,
                       icmp46_header_t *icmp0, u32 sw_if_index0,
                       u32 rx_fib_index0, vlib_node_runtime_t *node, u32 next0,
                       u32 thread_index, void *d, void *e)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 new_addr0, old_addr0, next0_tmp, fib_index;
  u16 old_id0, new_id0, port, checksum0;
  icmp_echo_header_t *echo0, *inner_echo0;
  icmp46_header_t *inner_icmp0;
  ip4_header_t *inner_ip0;
  ip4_address_t addr;
  void *l4_header;
  u8 dont_translate;
  ip_csum_t sum0;
  nat_protocol_t proto;

  echo0 = (icmp_echo_header_t *)(icmp0 + 1);
  next0_tmp =
      icmp_match_out2in_det (node, thread_index, b0, ip0, &addr, &port,
                             &fib_index, &proto, d, e, &dont_translate);
  if (next0_tmp != ~0)
    next0 = next0_tmp;
  if (next0 == DET44_OUT2IN_NEXT_DROP || dont_translate)
    goto out;

  if (PREDICT_TRUE (!ip4_is_fragment (ip0)))
    {
      sum0 = ip_incremental_checksum_buffer (
          vm, b0, (u8 *)icmp0 - (u8 *)vlib_buffer_get_current (b0),
          ntohs (ip0->length) - ip4_header_bytes (ip0), 0);
      checksum0 = ~ip_csum_fold (sum0);
      if (checksum0 != 0 && checksum0 != 0xffff)
        {
          next0 = DET44_OUT2IN_NEXT_DROP;
          goto out;
        }
    }

  old_addr0 = ip0->dst_address.as_u32;
  new_addr0 = ip0->dst_address.as_u32 = addr.as_u32;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = fib_index;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                         dst_address /* changed member */);
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
              sum0 =
                  ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
                                  identifier /* changed member */);
              icmp0->checksum = ip_csum_fold (sum0);
            }
        }
      else
        {
          inner_ip0 = (ip4_header_t *)(echo0 + 1);
          l4_header = ip4_next_header (inner_ip0);

          if (!ip4_header_checksum_is_valid (inner_ip0))
            {
              next0 = DET44_OUT2IN_NEXT_DROP;
              goto out;
            }

          old_addr0 = inner_ip0->src_address.as_u32;
          inner_ip0->src_address = addr;
          new_addr0 = inner_ip0->src_address.as_u32;

          sum0 = icmp0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                                 src_address /* changed member */);
          icmp0->checksum = ip_csum_fold (sum0);

          switch (proto)
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
              old_id0 = ((tcp_udp_header_t *)l4_header)->src_port;
              new_id0 = port;
              ((tcp_udp_header_t *)l4_header)->src_port = new_id0;

              sum0 = icmp0->checksum;
              sum0 = ip_csum_update (sum0, old_id0, new_id0, tcp_udp_header_t,
                                     src_port);
              icmp0->checksum = ip_csum_fold (sum0);
              break;
            default:
              ASSERT (0);
            }
        }
    }

out:
  return next0;
}
#endif

VLIB_NODE_FN (det44_out2in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from;
  u32 pkts_processed = 0;
  det44_main_t *dm = &det44_main;
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 next0 = DET44_OUT2IN_NEXT_LOOKUP;
      u32 sw_if_index0;
      ip4_header_t *ip0;
      ip_csum_t sum0;
      ip4_address_t new_addr0, old_addr0;
      u16 new_port0, old_port0, lo_port0, i0;
      udp_header_t *udp0;
      tcp_header_t *tcp0;
      u32 proto0;
      snat_det_out_key_t key0;
      u32 rx_fib_index0;
      icmp46_header_t *icmp0;

      /*******************************/
      my_map_t *mp0;
      my_session_t *ses0 = 0;
      /***********************************/

      b0 = *b;
      b++;

      ip0 = vlib_buffer_get_current (b0);
      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *)udp0;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      if (PREDICT_FALSE (ip0->ttl == 1))
        {
          vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32)~0;
          icmp4_error_set_vnet_buffer (
              b0, ICMP4_time_exceeded,
              ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
          next0 = DET44_OUT2IN_NEXT_ICMP_ERROR;
          goto trace00;
        }

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
        {
          rx_fib_index0 =
              ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
          icmp0 = (icmp46_header_t *)udp0;

          next0 =
              det44_icmp_out2in (b0, ip0, icmp0, sw_if_index0, rx_fib_index0,
                                 node, next0, thread_index, &ses0, &mp0);
          goto trace00;
        }

      //
      key0.ext_host_addr = ip0->src_address;
      key0.ext_host_port = tcp0->src;
      key0.out_port = tcp0->dst;

      /**********************************************************/

      // 根据 数据包目标ip（外部ip） 查找映射表
      // 从外部主机发送到nat的数据包
      // 此时 ip0->dst_address 即为 out_addr
      clib_bihash_kv_8_8_t kv;
      clib_bihash_kv_8_8_t value;
      kv.key = (u64)(ip0->dst_address.as_u32 & ip4_main.fib_masks[MY_PLEN])
               << 32;
      kv.value = 0;
      value.key = 0;
      value.value = 0;
      clib_bihash_search_8_8 (&det44_main.out_addr_hash_table, &kv, &value);

      if (PREDICT_FALSE (value.value >= MY_MAX_DET_MAPS))
        {
          // 没找到对应的映射表，处理错误逻辑
          det44_log_info ("no match mapping for internal host ip %U",
                          format_ip4_address, &ip0->src_address);
          next0 = DET44_OUT2IN_NEXT_DROP;
          b0->error = node->errors[DET44_OUT2IN_ERROR_NO_TRANSLATION];
          goto trace00;
        }

      mp0 = &dm->my_maps[value.value];

      if (PREDICT_FALSE (!mp0))
        {
          det44_log_info ("unknown dst address:  %U", format_ip4_address,
                          &ip0->dst_address);
          next0 = DET44_OUT2IN_NEXT_DROP;
          b0->error = node->errors[DET44_OUT2IN_ERROR_NO_TRANSLATION];
          goto trace00;
        }

      // 根据 外部ip，外部端口，计算 in_addr
      // 将转换后的 in_addr 存入 new_addr0
      u32 table_index = ip0->dst_address.as_u8[3];
      if (table_index >= 64)
        {
          det44_log_info ("invalid internal host ip %U", format_ip4_address,
                          &ip0->dst_address);
          next0 = DET44_OUT2IN_NEXT_DROP;
          b0->error = node->errors[DET44_OUT2IN_ERROR_NO_TRANSLATION];
          goto trace00;
        }

      my_session_table_t *table0 = &mp0->my_sessions_tables[table_index];

      // 将外部起始地址与偏移量相加得到映射到的外部地址
      bool is_find = false;
      for (u16 i = 0; i < 2; i++)
        {
          lo_port0 = 1024 * (i + 1);

          for (i0 = 0; i0 < MY_SESSIONS_PER_EXTERNAL_ADDR / 2; i0++)
            {
              ses0 = &table0->my_sessions[i0 + lo_port0];
              if (ses0->out.ext_host_addr.as_u32 ==
                      key0.ext_host_addr.as_u32 &&
                  ses0->out.ext_host_port == key0.ext_host_port)
                {
                  // 找到
                  new_port0 = i0 + lo_port0;
                  is_find = true;
                  break;
                }
            }
          if (is_find)
            break;
        }
      // 没找到
      if (!is_find)
        ses0 = 0;

      if (PREDICT_FALSE (!ses0))
        {
          det44_log_info ("no match src %U:%d dst %U:%d for user %U",
                          format_ip4_address, &ip0->src_address,
                          clib_net_to_host_u16 (tcp0->src), format_ip4_address,
                          &ip0->dst_address, clib_net_to_host_u16 (tcp0->dst),
                          format_ip4_address, &new_addr0);
          next0 = DET44_OUT2IN_NEXT_DROP;
          b0->error = node->errors[DET44_OUT2IN_ERROR_NO_TRANSLATION];
          goto trace00;
        }

      old_port0 = udp0->dst_port;
      udp0->dst_port = new_port0 = ses0->in_port;

      old_addr0 = ip0->dst_address;
      ip0->dst_address = new_addr0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = dm->inside_fib_index;

      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                             ip4_header_t, dst_address /* changed member */);
      ip0->checksum = ip_csum_fold (sum0);

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
        {
          if (tcp0->flags & TCP_FLAG_FIN &&
              ses0->state == DET44_SESSION_TCP_ESTABLISHED)
            ses0->state = DET44_SESSION_TCP_CLOSE_WAIT;
          else if (tcp0->flags & TCP_FLAG_ACK &&
                   ses0->state == DET44_SESSION_TCP_LAST_ACK)
            {
              // 将会话置零，会话数量减一
              if (clib_atomic_bool_cmp_and_swap (&ses0->in_port, ses0->in_port, 0))
                {
                  ses0 = 0;
                  clib_atomic_add_fetch (&table0->ses_num, -1);
                }
            }

          sum0 = tcp0->checksum;
          sum0 =
              ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                              ip4_header_t, dst_address /* changed member */);
          sum0 = ip_csum_update (sum0, old_port0, new_port0,
                                 ip4_header_t /* cheat */,
                                 length /* changed member */);
          tcp0->checksum = ip_csum_fold (sum0);
        }
      else if (udp0->checksum)
        {
          sum0 = udp0->checksum;
          sum0 =
              ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                              ip4_header_t, dst_address /* changed member */);
          sum0 = ip_csum_update (sum0, old_port0, new_port0,
                                 ip4_header_t /* cheat */,
                                 length /* changed member */);
          udp0->checksum = ip_csum_fold (sum0);
        }

    trace00:

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                         (b0->flags & VLIB_BUFFER_IS_TRACED)))
        {
          det44_out2in_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
          t->sw_if_index = sw_if_index0;
          t->next_index = next0;
          t->session_index = ~0;
          if (ses0)
            t->session_index = ses0 - table0->my_sessions;
        }

      pkts_processed += next0 != DET44_OUT2IN_NEXT_DROP;

      n_left_from--;
      next[0] = next0;
      next++;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *)nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, dm->out2in_node_index,
                               DET44_OUT2IN_ERROR_OUT2IN_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (det44_out2in_node) = {
    .name = "det44-out2in",
    .vector_size = sizeof (u32),
    .format_trace = format_det44_out2in_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = ARRAY_LEN (det44_out2in_error_strings),
    .error_strings = det44_out2in_error_strings,
    .runtime_data_bytes = sizeof (det44_runtime_t),
    .n_next_nodes = DET44_OUT2IN_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes =
        {
            [DET44_OUT2IN_NEXT_DROP] = "error-drop",
            [DET44_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
            [DET44_OUT2IN_NEXT_ICMP_ERROR] = "ip4-icmp-error",
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
