/*
 * jxt.h - deterministic NAT definitions
 *
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
 * @brief Deterministic NAT (CGN) definitions
 */

#ifndef __included_jxt_h__
#define __included_jxt_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_source.h>
#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vlibapi/api.h>
#include <vlib/log.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/reass/ip4_sv_reass.h>

#include <nat/lib/lib.h>
#include <nat/lib/inlines.h>
#include <nat/lib/ipfix_logging.h>

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>

/* Session state */
#define foreach_jxt_session_state         \
  _ (0, UNKNOWN, "unknown")                 \
  _ (1, UDP_ACTIVE, "udp-active")           \
  _ (2, TCP_SYN_SENT, "tcp-syn-sent")       \
  _ (3, TCP_ESTABLISHED, "tcp-established") \
  _ (4, TCP_FIN_WAIT, "tcp-fin-wait")       \
  _ (5, TCP_CLOSE_WAIT, "tcp-close-wait")   \
  _ (6, TCP_CLOSING, "tcp-closing")         \
  _ (7, TCP_LAST_ACK, "tcp-last-ack")       \
  _ (8, TCP_CLOSED, "tcp-closed")           \
  _ (9, ICMP_ACTIVE, "icmp-active")

typedef enum
{
#define _(v, N, s) jxt_SESSION_##N = v,
  foreach_jxt_session_state
#undef _
} jxt_session_state_t;

#define jxt_SES_PER_USER 1000

typedef struct
{
  u16 identifier;
  u16 sequence;
} icmp_echo_header_t;

typedef struct
{
  u16 src_port, dst_port;
} tcp_udp_header_t;

typedef struct
{
  u32 cached_sw_if_index;
  u32 cached_ip4_address;
} jxt_runtime_t;

/* deterministic session outside key */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t ext_host_addr;
      u16 ext_host_port;
      u16 out_port;
    };
    u64 as_u64;
  };
} snat_det_out_key_t;



typedef struct
{
  /* Inside network port */
  u16 in_port;
  /* Outside network address and port */
  snat_det_out_key_t out;
  /* Session state */
  u8 state;
  /* Expire timeout */
  u32 expire;

} snat_det_session_t;


typedef struct
{
  /* inside IP address range */
  ip4_address_t in_addr;
  u8 in_plen;
  /* outside IP address range */
  ip4_address_t out_addr;
  u8 out_plen;
  /* inside IP addresses / outside IP addresses */
  u32 sharing_ratio;
  /* number of ports available to internal host */
  u16 ports_per_host;
  /* session counter */
  u32 ses_num;
  /* vector of sessions */
  snat_det_session_t *sessions;
} snat_det_map_t;

typedef struct
{
  u32 sw_if_index;
  u8 flags;
} jxt_interface_t;

typedef struct
{
  u32 outside_vrf_id;
  u32 inside_vrf_id;
} jxt_config_t;

typedef struct
{
  u32 fib_index;
  u32 refcount;
} jxt_fib_t;

/*******************************************************/
/*********************** my modify begin *******************/
// 每个网段主机数量 
#define MY_USERS_PER_SEG 256
// 8k个用户
#define MY_USERS 8192
// 每个用户最多维护 2048 个会话
#define MY_MAX_SESS_PER_USER 2048
// in_port 可用端口个数，范围：1024-65535
#define MY_AVAI_PORT_NUM_BY_IN 65536
// 假设有两个外部端口范围
#define PORT_RANGE_1_START 1024
#define PORT_RANGE_1_END 3071
#define PORT_RANGE_2_START 3072
#define PORT_RANGE_2_END 5119
#define PORT_RANGE_SIZE 2048

typedef struct
{
  u16 in_port;
  u16 out_port;
  /* Session state */
  u8 state;
  /* Expire timeout */
  u32 expire;
  
} my_sess_t;


typedef struct
{
  /* inside IP address range */
  ip4_address_t in_addr;
  ip4_address_t out_addr;
  /* session counter */
  u32 ses_num;

  // 根据 in_port 得到会话的索引 my_sess_index_by_in[in_port]
  u16 my_sess_index_by_in[MY_AVAI_PORT_NUM_BY_IN];
  // 根据索引得到会话 my_sess[my_sess_index_by_in[in_port]]
  my_sess_t my_sess[MY_MAX_SESS_PER_USER];
  // 上一次 使用/创建 会话的索引
  u16 last_ses_index;
  // out_port 起始位置
  u16 lo_port;

} my_user_t;


typedef struct jxt_main_s
{
  jxt_config_t config;

  u32 outside_fib_index;
  u32 inside_fib_index;

  /* Vector of outside fibs */
  jxt_fib_t *outside_fibs;

  fib_source_t fib_src_hi;
  fib_source_t fib_src_low;

  u32 out2in_node_index;
  u32 in2out_node_index;

  /* Deterministic NAT mappings */
  snat_det_map_t *det_maps;

  /* TCP MSS clamping */
  u16 mss_clamping;

  /* Protocol timeouts */
  nat_timeouts_t timeouts;

  /* Expire walk process node index */
  u32 expire_walk_node_index;

  u32 enabled;

  /* API message ID base */
  u16 msg_id_base;

  /* log class */
  vlib_log_class_t log_class;

  jxt_interface_t *interfaces;

  /* convenience */
  ip4_main_t *ip4_main;
  /* required */
  vnet_main_t *vnet_main;

  /* --------------------my---------------------*/
  // 哈希表
  clib_bihash_8_8_t in_hash_table; 
  clib_bihash_8_8_t out_hash_table; 
  // 用户结构
  my_user_t my_users[MY_USERS];
  // 上一次 创建 用户结构的索引
  u16 last_user_index;
  u16 in_hash_items_num;

  /* --------------------my---------------------*/

} jxt_main_t;

extern jxt_main_t jxt_main;

/******************** my modify end *************************/
/***********************************************************/

/* logging */
#define jxt_log_err(...) \
  vlib_log (VLIB_LOG_LEVEL_ERR, jxt_main.log_class, __VA_ARGS__)
#define jxt_log_warn(...) \
  vlib_log (VLIB_LOG_LEVEL_WARNING, jxt_main.log_class, __VA_ARGS__)
#define jxt_log_notice(...) \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, jxt_main.log_class, __VA_ARGS__)
#define jxt_log_info(...) \
  vlib_log (VLIB_LOG_LEVEL_INFO, jxt_main.log_class, __VA_ARGS__)
#define jxt_log_debug(...) \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, jxt_main.log_class, __VA_ARGS__)

/* Deterministic NAT interface flags */
#define jxt_INTERFACE_FLAG_IS_INSIDE 1
#define jxt_INTERFACE_FLAG_IS_OUTSIDE 2

/** \brief Check if Deterministic NAT interface is inside.
    @param i Deterministic NAT interface
    @return 1 if inside interface
*/
#define jxt_interface_is_inside(i) i->flags &jxt_INTERFACE_FLAG_IS_INSIDE

/** \brief Check if Deterministic NAT interface is outside.
    @param i Deterministic NAT interface
    @return 1 if outside interface
*/
#define jxt_interface_is_outside(i) i->flags &jxt_INTERFACE_FLAG_IS_OUTSIDE

static_always_inline u8 plugin_enabled ()
{
  jxt_main_t *dm = &jxt_main;
  return dm->enabled;
}

extern vlib_node_registration_t jxt_in2out_node;
extern vlib_node_registration_t jxt_out2in_node;

int jxt_plugin_enable ();
int jxt_plugin_disable ();

int jxt_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del);

int jxt_set_timeouts (nat_timeouts_t *timeouts);
nat_timeouts_t jxt_get_timeouts ();
void jxt_reset_timeouts ();

/* format functions */
format_function_t format_det_map_ses;

int snat_det_add_map (ip4_address_t *in_addr, u8 in_plen,
                      ip4_address_t *out_addr, u8 out_plen, int is_add);

/* icmp session match functions */
u32 icmp_match_out2in_det (vlib_node_runtime_t *node, u32 thread_index,
                           vlib_buffer_t *b0, ip4_header_t *ip0,
                           ip4_address_t *addr, u16 *port, u32 *fib_index,
                           nat_protocol_t *proto, void *d, void *e,
                           u8 *dont_translate);
u32 icmp_match_in2out_det (vlib_node_runtime_t *node, u32 thread_index,
                           vlib_buffer_t *b0, ip4_header_t *ip0,
                           ip4_address_t *addr, u16 *port, u32 *fib_index,
                           nat_protocol_t *proto, void *d, void *e,
                           u8 *dont_translate);
u32 jxt_icmp_in2out (vlib_buffer_t *b0, ip4_header_t *ip0,
                       icmp46_header_t *icmp0, u32 sw_if_index0,
                       u32 rx_fib_index0, vlib_node_runtime_t *node, u32 next0,
                       u32 thread_index, void *d, void *e);
u32 jxt_icmp_out2in (vlib_buffer_t *b0, ip4_header_t *ip0,
                       icmp46_header_t *icmp0, u32 sw_if_index0,
                       u32 rx_fib_index0, vlib_node_runtime_t *node, u32 next0,
                       u32 thread_index, void *d, void *e);

static_always_inline int is_addr_in_net (ip4_address_t *addr,
                                         ip4_address_t *net, u8 plen)
{
  // 将ip地址与子网掩码按位与，然后比较网络地址是否相等
  if (net->as_u32 == (addr->as_u32 & ip4_main.fib_masks[plen]))
    return 1;
  return 0;
}

// 根据用户的IPv4地址查找并返回对应的SNAT映射
static_always_inline snat_det_map_t *
snat_det_map_by_user (ip4_address_t *user_addr)
{
  jxt_main_t *dm = &jxt_main;
  snat_det_map_t *mp;
  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps) // 遍历
  {
    // 判断 源ip 是不是在 该子网内
    if (is_addr_in_net (user_addr, &mp->in_addr, mp->in_plen))
      return mp;
  }
  /* *INDENT-ON* */
  return 0;
}

// 根据外部（公网）IPv4地址查找对应的SNAT映射
static_always_inline snat_det_map_t *
snat_det_map_by_out (ip4_address_t *out_addr)
{
  jxt_main_t *dm = &jxt_main;
  snat_det_map_t *mp;
  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps)
  {
    if (is_addr_in_net (out_addr, &mp->out_addr, mp->out_plen))
      return mp;
  }
  /* *INDENT-ON* */
  return 0;
}

// 根据 映射表 和 内部地址 计算 外部地址 和 端口
// dm 为映射表
static_always_inline void snat_det_forward (snat_det_map_t *dm,
                                            ip4_address_t *in_addr,
                                            ip4_address_t *out_addr,
                                            u16 *lo_port)
{
  u32 in_offset, out_offset;

  // 内部地址 的偏移量
  // dm->in_addr.as_u32 为起始地址
  in_offset = clib_net_to_host_u32 (in_addr->as_u32) -
              clib_net_to_host_u32 (dm->in_addr.as_u32);
  //
  out_offset = in_offset / dm->sharing_ratio;

  // 计算得到 外部地址
  out_addr->as_u32 = clib_host_to_net_u32 (
      clib_net_to_host_u32 (dm->out_addr.as_u32) + out_offset);
  // 计算得到 临时外部端口
  *lo_port = 1024 + dm->ports_per_host * (in_offset % dm->sharing_ratio);
}

//
static_always_inline void snat_det_reverse (snat_det_map_t *dm,
                                            ip4_address_t *out_addr,
                                            u16 out_port,
                                            ip4_address_t *in_addr)
{
  u32 in_offset1, in_offset2, out_offset;

  out_offset = clib_net_to_host_u32 (out_addr->as_u32) -
               clib_net_to_host_u32 (dm->out_addr.as_u32);
  in_offset1 = out_offset * dm->sharing_ratio;
  in_offset2 = (out_port - 1024) / dm->ports_per_host;
  in_addr->as_u32 = clib_host_to_net_u32 (
      clib_net_to_host_u32 (dm->in_addr.as_u32) + in_offset1 + in_offset2);
}

static_always_inline u32 snat_det_user_ses_offset (ip4_address_t *addr,
                                                   u8 plen)
{
  return (clib_net_to_host_u32 (addr->as_u32) & pow2_mask (32 - plen)) *
         jxt_SES_PER_USER;
}

static_always_inline snat_det_session_t *
snat_det_get_ses_by_out (snat_det_map_t *dm, ip4_address_t *in_addr,
                         u64 out_key)
{
  u32 user_offset;
  u16 i;

  user_offset = snat_det_user_ses_offset (in_addr, dm->in_plen);
  for (i = 0; i < jxt_SES_PER_USER; i++)
    {
      if (dm->sessions[i + user_offset].out.as_u64 == out_key)
        return &dm->sessions[i + user_offset];
    }

  return 0;
}

static_always_inline snat_det_session_t *
snat_det_find_ses_by_in (snat_det_map_t *dm, ip4_address_t *in_addr,
                         u16 in_port, snat_det_out_key_t out_key)
{
  snat_det_session_t *ses;
  u32 user_offset;
  u16 i;

  user_offset = snat_det_user_ses_offset (in_addr, dm->in_plen);
  for (i = 0; i < jxt_SES_PER_USER; i++)
    {
      ses = &dm->sessions[i + user_offset];
      if (ses->in_port == in_port &&
          ses->out.ext_host_addr.as_u32 == out_key.ext_host_addr.as_u32 &&
          ses->out.ext_host_port == out_key.ext_host_port)
        return &dm->sessions[i + user_offset];
    }

  return 0;
}

static_always_inline snat_det_session_t *
snat_det_ses_create (u32 thread_index, snat_det_map_t *dm,
                     ip4_address_t *in_addr, u16 in_port,
                     snat_det_out_key_t *out)
{
  u32 user_offset;
  u16 i;

  user_offset = snat_det_user_ses_offset (in_addr, dm->in_plen);

  for (i = 0; i < jxt_SES_PER_USER; i++)
    {
      if (!dm->sessions[i + user_offset].in_port)
        {
          if (clib_atomic_bool_cmp_and_swap (
                  &dm->sessions[i + user_offset].in_port, 0, in_port))
            {
              dm->sessions[i + user_offset].out.as_u64 = out->as_u64;
              dm->sessions[i + user_offset].state = jxt_SESSION_UNKNOWN;
              dm->sessions[i + user_offset].expire = 0;
              clib_atomic_add_fetch (&dm->ses_num, 1);
              return &dm->sessions[i + user_offset];
            }
        }
    }

  // nat_ipfix_logging_max_entries_per_user (thread_index, jxt_SES_PER_USER,
  //                                         in_addr->as_u32);
  return 0;
}

static_always_inline void snat_det_ses_close (snat_det_map_t *dm,
                                              snat_det_session_t *ses)
{
  if (clib_atomic_bool_cmp_and_swap (&ses->in_port, ses->in_port, 0))
    {
      ses->out.as_u64 = 0;
      clib_atomic_add_fetch (&dm->ses_num, -1);
    }
}

clib_error_t *jxt_api_hookup (vlib_main_t *vm);

#endif /* __included_jxt_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
