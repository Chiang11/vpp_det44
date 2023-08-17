/*
 * jxt.c - deterministic NAT
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
 * @brief deterministic NAT (CGN)
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>

#include <plugins/jxt/jxt.h>

jxt_main_t jxt_main;

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_jxt_in2out, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "jxt-in2out",
    .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                                 "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_jxt_out2in, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "jxt-out2in",
    .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                                 "ip4-sv-reassembly-feature",
                                 "ip4-dhcp-client-detect"),
};
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Deterministic NAT (CGN)",
};
/* *INDENT-ON* */

// 该函数作用是将指定的IP地址和子网前缀添加或删除到FIB中，并与指定的接口（sw_if_index）关联。
// FIB是路由表的一种数据结构，用于存储网络中不同子网的路由信息，它决定了数据包从源地址到目标地址的转发路径。
void jxt_add_del_addr_to_fib (ip4_address_t *addr, u8 p_len, u32 sw_if_index,
                              int is_add)
{
  jxt_main_t *dm = &jxt_main;
  fib_prefix_t prefix = {
      .fp_len = p_len,
      .fp_proto = FIB_PROTOCOL_IP4,
      .fp_addr =
          {
              .ip4.as_u32 = addr->as_u32,
          },
  };
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (is_add) // 添加
    {
      fib_table_entry_update_one_path (fib_index, &prefix, dm->fib_src_low,
                                       (FIB_ENTRY_FLAG_CONNECTED |
                                        FIB_ENTRY_FLAG_LOCAL |
                                        FIB_ENTRY_FLAG_EXCLUSIVE),
                                       DPO_PROTO_IP4, NULL, sw_if_index, ~0, 1,
                                       NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      fib_table_entry_delete (fib_index, &prefix, dm->fib_src_low);
    }
}

/**
 * @brief Add/delete deterministic NAT mapping.
 *
 * Create bijective mapping of inside address to outside address and port range
 * pairs, with the purpose of enabling deterministic NAT to reduce logging in
 * CGN deployments.
 *
 * @param in_addr  Inside network address.
 * @param in_plen  Inside network prefix length.
 * @param out_addr Outside network address.
 * @param out_plen Outside network prefix length.
 * @param is_add   If 0 delete, otherwise add.
 */

// 这个函数的作用是在jxt功能中管理静态映射规则，
// 可以添加或删除指定的内部IP地址和端口到外部（公共）IP地址和端口的映射规则，同时管理相关的FIB路由表项和会话空间。
int snat_det_add_map (ip4_address_t *in_addr, u8 in_plen,
                      ip4_address_t *out_addr, u8 out_plen, int is_add)
{
  static snat_det_session_t empty_snat_det_session = {0};
  jxt_main_t *dm = &jxt_main;
  ip4_address_t in_cmp, out_cmp;
  jxt_interface_t *i;
  snat_det_map_t *mp;
  u8 found = 0;

  in_cmp.as_u32 = in_addr->as_u32 & ip4_main.fib_masks[in_plen];
  out_cmp.as_u32 = out_addr->as_u32 & ip4_main.fib_masks[out_plen];
  vec_foreach (mp, dm->det_maps)
  {
    /* Checking for overlapping addresses to be added here */
    if (mp->in_addr.as_u32 == in_cmp.as_u32 && mp->in_plen == in_plen &&
        mp->out_addr.as_u32 == out_cmp.as_u32 && mp->out_plen == out_plen)
      {
        found = 1; // 表示找到
        break;
      }
  }

  /* If found, don't add again */
  if (found && is_add)
    return VNET_API_ERROR_VALUE_EXIST;

  /* If not found, don't delete */
  if (!found && !is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (is_add)
    {
      pool_get (dm->det_maps, mp);
      clib_memset (mp, 0, sizeof (*mp));
      mp->in_addr.as_u32 = in_cmp.as_u32;
      mp->in_plen = in_plen;
      mp->out_addr.as_u32 = out_cmp.as_u32;
      mp->out_plen = out_plen;
      mp->sharing_ratio = (1 << (32 - in_plen)) / (1 << (32 - out_plen));
      mp->ports_per_host = (65535 - 1023) / mp->sharing_ratio;

      // 初始化 所有会话 并默认为0
      vec_validate_init_empty (mp->sessions,
                               jxt_SES_PER_USER * (1 << (32 - in_plen)) - 1,
                               empty_snat_det_session);
    }
  else
    {
      vec_free (mp->sessions);
      vec_del1 (dm->det_maps, mp - dm->det_maps);
    }

  /* Add/del external address range to FIB */
  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces)
  {
    if (jxt_interface_is_inside (i))
      continue;
    jxt_add_del_addr_to_fib (out_addr, out_plen, i->sw_if_index, is_add);
    goto out;
  }
  /* *INDENT-ON* */
out:
  return 0;
}

// 设置jxt功能的会话超时时间
int jxt_set_timeouts (nat_timeouts_t *timeouts)
{
  jxt_main_t *dm = &jxt_main;
  if (timeouts->udp)
    dm->timeouts.udp = timeouts->udp;
  if (timeouts->tcp.established)
    dm->timeouts.tcp.established = timeouts->tcp.established;
  if (timeouts->tcp.transitory)
    dm->timeouts.tcp.transitory = timeouts->tcp.transitory;
  if (timeouts->icmp)
    dm->timeouts.icmp = timeouts->icmp;
  return 0;
}

// 获取jxt功能当前的会话超时时间
nat_timeouts_t jxt_get_timeouts ()
{
  jxt_main_t *dm = &jxt_main;
  return dm->timeouts;
}

// 用于将jxt功能的会话超时时间重置为默认值
void jxt_reset_timeouts ()
{
  jxt_main_t *dm = &jxt_main;
  nat_reset_timeouts (&dm->timeouts);
}

// 实现了在 jxt 功能中添加或删除接口，并根据接口类型启用或禁用相应的功能。
// sw_if_index 接口的软件索引，用于标识接口。
int jxt_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del)
{
  jxt_main_t *dm = &jxt_main;
  jxt_interface_t *tmp, *i = 0;
  const char *feature_name;
  int rv;

  // TODO: if plugin is not enabled do not register nodes on interfaces
  // rather make a structure and when enable call is used
  // then register nodes

  /* *INDENT-OFF* */
  pool_foreach (tmp, dm->interfaces)
  {
    if (tmp->sw_if_index == sw_if_index)
      {
        i = tmp;
        goto out;
      }
  }
  /* *INDENT-ON* */
out:

  feature_name = is_inside ? "jxt-in2out" : "jxt-out2in";

  if (is_del)
    {
      if (!i)
        {
          jxt_log_err ("jxt is not enabled on this interface");
          return VNET_API_ERROR_INVALID_VALUE;
        }

      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
        return rv;

      rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                        sw_if_index, 1, 0, 0);
      if (rv)
        return rv;

      pool_put (dm->interfaces, i);
    }
  else
    {
      if (i)
        {
          jxt_log_err ("jxt is already enabled on this interface");
          return VNET_API_ERROR_INVALID_VALUE;
        }

      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
        return rv;

      rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                        sw_if_index, 1, 0, 0);
      if (rv)
        return rv;

      pool_get (dm->interfaces, i);
      clib_memset (i, 0, sizeof (*i));

      i->sw_if_index = sw_if_index;

      if (is_inside)
        i->flags |= jxt_INTERFACE_FLAG_IS_INSIDE;
      else
        i->flags |= jxt_INTERFACE_FLAG_IS_OUTSIDE;
    }

  if (!is_inside)
    {
      u32 fib_index =
          fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);
      // add/del outside interface fib to registry
      u8 found = 0;
      jxt_fib_t *outside_fib;
      /* *INDENT-OFF* */
      vec_foreach (outside_fib, dm->outside_fibs)
      {
        if (outside_fib->fib_index == fib_index)
          {
            if (!is_del)
              {
                outside_fib->refcount++;
              }
            else
              {
                outside_fib->refcount--;
                if (!outside_fib->refcount)
                  {
                    vec_del1 (dm->outside_fibs,
                              outside_fib - dm->outside_fibs);
                  }
              }
            found = 1;
            break;
          }
      }
      /* *INDENT-ON* */
      if (!is_del && !found)
        {
          vec_add2 (dm->outside_fibs, outside_fib, 1);
          outside_fib->fib_index = fib_index;
          outside_fib->refcount = 1;
        }
      // add/del outside address to FIB
      snat_det_map_t *mp;
      /* *INDENT-OFF* */
      pool_foreach (mp, dm->det_maps)
      {
        jxt_add_del_addr_to_fib (&mp->out_addr, mp->out_plen, sw_if_index,
                                 !is_del);
      }
      /* *INDENT-ON* */
    }
  return 0;
}

/**
 * @brief The 'jxt-expire-walk' process's main loop.
 *
 * Check expire time for active sessions.
 */
// 进程的处理函数，定期扫描jxt会话，检查是否有过期的会话，并将其关闭
// 在每次执行时，会遍历jxt插件中的所有jxt映射表，并检查每个映射表中的会话是否过期。
static uword jxt_expire_walk_fn (vlib_main_t *vm, vlib_node_runtime_t *rt,
                                 vlib_frame_t *f)
{
  jxt_main_t *dm = &jxt_main;
  snat_det_session_t *ses;
  snat_det_map_t *mp;

  vlib_process_wait_for_event_or_clock (vm, 10.0);
  vlib_process_get_events (vm, NULL);
  u32 now = (u32)vlib_time_now (vm);
  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps)
  {
    vec_foreach (ses, mp->sessions)
    {
      /* Delete if session expired */
      if (ses->in_port && (ses->expire < now))
        snat_det_ses_close (mp, ses);
    }
  }
  /* *INDENT-ON* */
  return 0;
}

// 用于创建处理过期会话的进程
void jxt_create_expire_walk_process ()
{
  jxt_main_t *dm = &jxt_main;

  if (dm->expire_walk_node_index)
    return;

  dm->expire_walk_node_index =
      vlib_process_create (vlib_get_main (), "jxt-expire-walk",
                           jxt_expire_walk_fn, 16 /* stack_bytes */);
}

// 启用jxt插件
int jxt_plugin_enable (jxt_config_t c)
{
  jxt_main_t *dm = &jxt_main;

  if (plugin_enabled () == 1)
    {
      jxt_log_err ("plugin already enabled!");
      return 1;
    }

  jxt_log_err ("inside %u, outside %u", c.inside_vrf_id, c.outside_vrf_id);

  // 创建内部和外部FIB（Forwarding Information Base）表，并为其绑定相应的VRF
  // ID。
  dm->outside_fib_index = fib_table_find_or_create_and_lock (
      FIB_PROTOCOL_IP4, c.outside_vrf_id, dm->fib_src_hi);
  dm->inside_fib_index = fib_table_find_or_create_and_lock (
      FIB_PROTOCOL_IP4, c.inside_vrf_id, dm->fib_src_hi);

  jxt_create_expire_walk_process (); // 创建并启动处理过期会话的进程
  dm->mss_clamping = 0;
  dm->config = c;
  dm->enabled = 1;

  /*-------------------------------------------------------------*/
  u16 i0, j0;

  // 初始化上一次 创建用户索引 为最大值
  dm->last_user_index = MY_USERS - 1;
  dm->in_hash_items_num = 0;

  // 分配内存
  static my_sess_t empty_my_sess = {0};
  static ip4_address_t empty_my_addr = {0};

  // 初始化每个用户结构
  for (i0 = 0; i0 < MY_USERS; i0++)
    {
      // 初始化映射表的成员变量
      dm->my_users[i0].ses_num = 0;
      // 初始化 in_addr 和 out_addr 全零
      dm->my_users[i0].in_addr = empty_my_addr;
      dm->my_users[i0].out_addr = empty_my_addr;

      // 32 * 128 = 4096
      // 10.2.0.0 - 10.2.0.127
      // ...
      // 10.2.31.0 - 10.2.31.127
      // 初始化 out_addr
      #ifdef is_TEST
            // 这里是仅在宏 is_TEST 被定义时执行的代码
            dm->my_users[i0].out_addr.as_u32 =
                clib_host_to_net_u32 (0x0AE9E90A); // 10.233.233.10
      #else
            // 这里是在宏 is_TEST 未被定义时执行的代码
            dm->my_users[i0].out_addr.as_u32 =
                clib_host_to_net_u32 (0x0A020000) +
                clib_host_to_net_u32 ((i0 / MY_USERS_PER_SEG) << 8) +
                clib_host_to_net_u32 ((i0 % MY_USERS_PER_SEG) / 2);
      #endif

      // 初始化 会话索引 为非法值
      memset (dm->my_users[i0].my_sess_index_by_in, ~0,
              MY_AVAI_PORT_NUM_BY_IN * sizeof (u16));

      // 初始化 会话表 全零
      for (j0 = 0; j0 < MY_MAX_SESS_PER_USER; j0++)
        {
          dm->my_users[i0].my_sess[j0] = empty_my_sess;
        }

      // 初始化上一次 会话 索引为最大值
      dm->my_users[i0].last_ses_index = MY_MAX_SESS_PER_USER - 1;

      // 初始化每个 in_addr 对应的外部端口范围
      dm->my_users[i0].lo_port = 1024 + 2048 * (i0 % 2);
    }

  // 创建 in_addr -> my_user索引 的哈希表
  clib_bihash_init_8_8 (&dm->in_hash_table, "my_in_hash_table", MY_USERS, 0);
  // 创建 out_addr + out_port -> my_user索引 的哈希表
  clib_bihash_init_8_8 (&dm->out_hash_table, "my_out_hash_table", MY_USERS, 0);

  clib_bihash_kv_8_8_t kv;
  // 初始化 out 哈希表
  for (i0 = 0; i0 < MY_USERS; i0++)
    {
      // out_hash_table
      // 将每个 out_addr 和 out_port (0或1)
      // 作为键，映射表的索引作为值，插入哈希表 10.2.0.0 + 0 -> 0 10.2.0.0 + 1
      // -> 1 10.2.0.1 + 0 -> 2
      // ...
      // 10.2.0.127 + 1 -> 255
      // 10.2.1.0 + 0 -> 256
      if (i0 % 2 == 0)
        {
          kv.key = (u64)(((u64)dm->my_users[i0].out_addr.as_u32 << 32) + 0);
          kv.value = i0;
          clib_bihash_add_del_8_8 (&jxt_main.out_hash_table, &kv, 1);
        }
      if (i0 % 2 == 1)
        {
          kv.key = (u64)(((u64)dm->my_users[i0].out_addr.as_u32 << 32) + 1);
          kv.value = i0;
          clib_bihash_add_del_8_8 (&jxt_main.out_hash_table, &kv, 1);
        }
    }

  return 0;
}

// 禁用jxt插件
int jxt_plugin_disable ()
{
  jxt_main_t *dm = &jxt_main;
  jxt_interface_t *i, *interfaces;
  snat_det_map_t *mp;
  int rv = 0;

  if (plugin_enabled () == 0)
    {
      jxt_log_err ("plugin already disabled!");
      return 1;
    }

  // jxt cleanup (order dependent)
  // 1) remove interfaces (jxt_interface_add_del) removes map ranges from fib
  // 2) free sessions
  // 3) free maps

  interfaces = vec_dup (dm->interfaces);
  vec_foreach (i, interfaces)
  {
    vnet_main_t *vnm = vnet_get_main ();

    if (i->flags & jxt_INTERFACE_FLAG_IS_INSIDE)
      {
        rv = jxt_interface_add_del (i->sw_if_index, i->flags, 1);
        if (rv)
          {
            jxt_log_err ("inside interface %U del failed",
                         unformat_vnet_sw_interface, vnm, i->sw_if_index);
          }
      }

    if (i->flags & jxt_INTERFACE_FLAG_IS_OUTSIDE)
      {
        rv = jxt_interface_add_del (i->sw_if_index, i->flags, 1);
        if (rv)
          {
            jxt_log_err ("outside interface %U del failed",
                         unformat_vnet_sw_interface, vnm, i->sw_if_index);
          }
      }
  }
  vec_free (interfaces);

  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps)
  {
    vec_free (mp->sessions);
  }
  /* *INDENT-ON* */

  jxt_reset_timeouts ();
  dm->enabled = 0;

  pool_free (dm->interfaces);
  pool_free (dm->det_maps);

  return rv;
}

// jxt插件维护了一个外部FIB表列表，其中每个元素代表一个外部FIB表，并记录了该FIB表的索引和引用计数。
// 引用计数用于跟踪当前使用该FIB表的接口数量，当引用计数为0时，表示该FIB表不再被使用，可以从列表中移除。
static void jxt_update_outside_fib (ip4_main_t *im, uword opaque,
                                    u32 sw_if_index, u32 new_fib_index,
                                    u32 old_fib_index)
{
  jxt_main_t *dm = &jxt_main;

  jxt_fib_t *outside_fib;
  jxt_interface_t *i;

  u8 is_add = 1;
  u8 match = 0;

  if (plugin_enabled () == 0)
    return;

  if (new_fib_index == old_fib_index)
    return;

  if (!vec_len (dm->outside_fibs))
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces)
  {
    if (i->sw_if_index == sw_if_index)
      {
        if (!(jxt_interface_is_outside (i)))
          return;
        match = 1;
      }
  }
  /* *INDENT-ON* */

  if (!match)
    return;

  vec_foreach (outside_fib, dm->outside_fibs)
  {
    if (outside_fib->fib_index == old_fib_index)
      {
        outside_fib->refcount--;
        if (!outside_fib->refcount)
          vec_del1 (dm->outside_fibs, outside_fib - dm->outside_fibs);
        break;
      }
  }

  vec_foreach (outside_fib, dm->outside_fibs)
  {
    if (outside_fib->fib_index == new_fib_index)
      {
        outside_fib->refcount++;
        is_add = 0;
        break;
      }
  }

  if (is_add)
    {
      vec_add2 (dm->outside_fibs, outside_fib, 1);
      outside_fib->refcount = 1;
      outside_fib->fib_index = new_fib_index;
    }
}

// jxt插件的初始化
// 获取 jxt_in2out 和 jxt_out2in 节点的索引、分配 FIB 源、注册 FIB
// 表绑定回调函数和重置超时值等。
static clib_error_t *jxt_init (vlib_main_t *vm)
{
  jxt_main_t *dm = &jxt_main;
  ip4_table_bind_callback_t cb;
  vlib_node_t *node;

  clib_memset (dm, 0, sizeof (*dm));

  dm->ip4_main = &ip4_main;
  dm->log_class = vlib_log_register_class ("jxt", 0);

  // 获取节点索引
  node = vlib_get_node_by_name (vm, (u8 *)"jxt-in2out");
  dm->in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *)"jxt-out2in");
  dm->out2in_node_index = node->index;

  dm->fib_src_hi = fib_source_allocate ("jxt-hi", FIB_SOURCE_PRIORITY_HI,
                                        FIB_SOURCE_BH_SIMPLE);
  dm->fib_src_low = fib_source_allocate ("jxt-low", FIB_SOURCE_PRIORITY_LOW,
                                         FIB_SOURCE_BH_SIMPLE);

  // 设置回调函数并添加
  cb.function = jxt_update_outside_fib;
  cb.function_opaque = 0;
  vec_add1 (dm->ip4_main->table_bind_callbacks, cb);

  jxt_reset_timeouts (); // 重置超时值
  return 0;
  // return jxt_api_hookup (vm);
}

// 在VPP启动时调用jxt_init函数，从而完成jxt插件的初始化过程。
VLIB_INIT_FUNCTION (jxt_init);

// 将jxt会话的状态枚举值转换为对应的字符串表示
u8 *format_jxt_session_state (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, N, str)    \
  case jxt_SESSION_##N: \
    t = (u8 *)str;      \
    break;
      foreach_jxt_session_state
#undef _
          default : t = format (t, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

// 格式化输出jxt映射表的会话信息。
u8 *format_det_map_ses (u8 *s, va_list *args)
{
  snat_det_map_t *det_map = va_arg (*args, snat_det_map_t *);
  ip4_address_t in_addr, out_addr;
  u32 in_offset, out_offset;
  snat_det_session_t *ses = va_arg (*args, snat_det_session_t *);
  u32 *i = va_arg (*args, u32 *);

  u32 user_index = *i / jxt_SES_PER_USER;
  in_addr.as_u32 = clib_host_to_net_u32 (
      clib_net_to_host_u32 (det_map->in_addr.as_u32) + user_index);
  in_offset = clib_net_to_host_u32 (in_addr.as_u32) -
              clib_net_to_host_u32 (det_map->in_addr.as_u32);
  out_offset = in_offset / det_map->sharing_ratio;
  out_addr.as_u32 = clib_host_to_net_u32 (
      clib_net_to_host_u32 (det_map->out_addr.as_u32) + out_offset);
  s = format (
      s, "in %U:%d out %U:%d external host %U:%d state: %U expire: %d\n",
      format_ip4_address, &in_addr, clib_net_to_host_u16 (ses->in_port),
      format_ip4_address, &out_addr, clib_net_to_host_u16 (ses->out.out_port),
      format_ip4_address, &ses->out.ext_host_addr,
      clib_net_to_host_u16 (ses->out.ext_host_port), format_jxt_session_state,
      ses->state, ses->expire);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */