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
 * @brief jxt CLI
 */
#include <plugins/jxt/jxt.h>

static clib_error_t *jxt_map_command_fn (vlib_main_t *vm,
                                           unformat_input_t *input,
                                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u32 in_plen, out_plen;
  int is_add = 1, rv;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U/%u", unformat_ip4_address, &in_addr,
                    &in_plen))
        ;
      else if (unformat (line_input, "out %U/%u", unformat_ip4_address,
                         &out_addr, &out_plen))
        ;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  rv = snat_det_add_map (&in_addr, (u8)in_plen, &out_addr, (u8)out_plen,
                         is_add);

  if (rv)
    {
      error = clib_error_return (0, "snat_det_add_map return %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *jxt_show_mappings_command_fn (vlib_main_t *vm,
                                                     unformat_input_t *input,
                                                     vlib_cli_command_t *cmd)
{
  jxt_main_t *dm = &jxt_main;
  snat_det_map_t *mp;
  vlib_cli_output (vm, "NAT44 deterministic mappings:");
  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps)
  {
    vlib_cli_output (vm, " in %U/%d out %U/%d\n", format_ip4_address,
                     &mp->in_addr, mp->in_plen, format_ip4_address,
                     &mp->out_addr, mp->out_plen);
    vlib_cli_output (vm, "  outside address sharing ratio: %d\n",
                     mp->sharing_ratio);
    vlib_cli_output (vm, "  number of ports per inside host: %d\n",
                     mp->ports_per_host);
    vlib_cli_output (vm, "  sessions number: %d\n", mp->ses_num);
  }
  /* *INDENT-ON* */
  return 0;
}


/////////////////////////////////////////////////////////////////
// my function
//////////////////////////////////////////////////////////////
static clib_error_t *
jxt_show_my_mappings_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  jxt_main_t *dm = &jxt_main;
  my_user_t *user0;
  vlib_cli_output (vm, "jxt deterministic mappings:");

  for (u16 i0 = 0; i0 < MY_USERS; i0++)
  {
    user0 = &dm->my_users[i0];
    if(user0->in_addr.as_u32 != 0)
    {
      vlib_cli_output (vm, " in %U out %U start_port: %d\n", format_ip4_address,
                      &user0->in_addr, format_ip4_address,
                      &user0->out_addr, user0->lo_port);
    }
    
  }
  
  // pool_foreach (mp, dm->my_maps) // 不能用pool_foreach，应该用vec_foreach？？
  // {
  //   if(mp->in_plen == 0)
  //   {
  //     vlib_cli_output (vm, "please enable jxt first");
  //     return 0;
  //   }
  //   vlib_cli_output (vm, " in %U/%d out %U/%d\n", format_ip4_address,
  //                     &mp->in_addr, mp->in_plen, format_ip4_address,
  //                     &mp->out_addr, mp->out_plen);
  // }
  /* *INDENT-ON* */
  return 0;
}



/********************* show in hash ****************************/
static clib_error_t *
jxt_show_my_in_hash_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  jxt_main_t *dm = &jxt_main;

  clib_bihash_kv_8_8_t kv0;
  clib_bihash_kv_8_8_t kv;
  u32 value;
  int rv;
  u16 i0;

  vlib_cli_output (vm, "jxt in_hash:");
  for (i0 = 0; i0 < MY_USERS; i0++) 
  {
    // 构造要查找的键
    kv0.key = (u64)dm->my_users[i0].in_addr.as_u32 << 32;
    kv0.value = 0;
    kv.key = 0;
    kv.value = 0;

    // 在哈希表中查找键对应的值
    rv = clib_bihash_search_8_8(&jxt_main.in_hash_table, &kv0, &kv);

    if (rv == 0) {
        // 键存在于哈希表中，输出键值对的内容
        value = kv.value;
        vlib_cli_output (vm, "键: %U, 值: %u\n", format_ip4_address,
                      &dm->my_users[i0].in_addr, value);
    } else {
        // 键不存在于哈希表中，输出未找到的信息
        vlib_cli_output (vm, "未找到键: %U\n", format_ip4_address,
                      &dm->my_users[i0].in_addr);
    }
  }
  return 0;
}


/********************* show out hash ****************************/
static clib_error_t *
jxt_show_my_out_hash_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  jxt_main_t *dm = &jxt_main;

  clib_bihash_kv_8_8_t kv0;
  clib_bihash_kv_8_8_t kv;
  u32 value;
  int rv;
  u16 i0;

  vlib_cli_output (vm, "jxt out_hash:");
  for (i0 = 0; i0 < MY_USERS; i0++) 
  {
    if(i0 % 2 ==0)
    {
      // 构造要查找的键
      kv0.key = (u64)(((u64)dm->my_users[i0].out_addr.as_u32 << 32) + 0);
      kv0.value = 0;
      kv.key = 0;
      kv.value = 0;

      // 在哈希表中查找键对应的值
      rv = clib_bihash_search_8_8(&jxt_main.out_hash_table, &kv0, &kv);

      if (rv == 0) {
          // 键存在于哈希表中，输出键值对的内容
          value = kv.value;
          vlib_cli_output (vm, "键: %U, lo_port: %d, 值: %u\n", format_ip4_address,
                      &dm->my_users[i0].out_addr, dm->my_users[i0].lo_port, value);
      } else {
          // 键不存在于哈希表中，输出未找到的信息
          vlib_cli_output (vm, "未找到键: %llu\n", kv0.key);
      }
    }
    else
    {
      // 构造要查找的键
      kv0.key = (u64)(((u64)dm->my_users[i0].out_addr.as_u32 << 32) + 1);
      kv0.value = 0;
      kv.key = 0;
      kv.value = 0;

      // 在哈希表中查找键对应的值
      rv = clib_bihash_search_8_8(&jxt_main.out_hash_table, &kv0, &kv);

      if (rv == 0) {
          // 键存在于哈希表中，输出键值对的内容
          value = kv.value;
          vlib_cli_output (vm, "键: %U, lo_port: %d, 值: %u\n", format_ip4_address,
                      &dm->my_users[i0].out_addr, dm->my_users[i0].lo_port, value);
      } else {
          // 键不存在于哈希表中，输出未找到的信息
          vlib_cli_output (vm, "未找到键: %llu\n", kv0.key);
      }
    }
  }
  return 0;
}


static clib_error_t *jxt_forward_command_fn (vlib_main_t *vm,
                                               unformat_input_t *input,
                                               vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u16 lo_port;
  snat_det_map_t *mp;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &in_addr))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  mp = snat_det_map_by_user (&in_addr);
  if (!mp)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_forward (mp, &in_addr, &out_addr, &lo_port);
      vlib_cli_output (vm, "%U:<%d-%d>", format_ip4_address, &out_addr,
                       lo_port, lo_port + mp->ports_per_host - 1);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *jxt_reverse_command_fn (vlib_main_t *vm,
                                               unformat_input_t *input,
                                               vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  clib_error_t *error = 0;
  snat_det_map_t *mp;
  u32 out_port;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d", unformat_ip4_address, &out_addr,
                    &out_port))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  if (out_port < 1024 || out_port > 65535)
    {
      error = clib_error_return (0, "wrong port, must be <1024-65535>");
      goto done;
    }

  mp = snat_det_map_by_out (&out_addr);
  if (!mp)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_reverse (mp, &out_addr, (u16)out_port, &in_addr);
      vlib_cli_output (vm, "%U", format_ip4_address, &in_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *jxt_show_sessions_command_fn (vlib_main_t *vm,
                                                     unformat_input_t *input,
                                                     vlib_cli_command_t *cmd)
{
  jxt_main_t *dm = &jxt_main;
  snat_det_session_t *ses;
  snat_det_map_t *mp;
  vlib_cli_output (vm, "NAT44 deterministic sessions:");
  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps)
  {
    int i;
    vec_foreach_index (i, mp->sessions)
    {
      ses = vec_elt_at_index (mp->sessions, i);
      if (ses->in_port)
        vlib_cli_output (vm, "  %U", format_det_map_ses, mp, ses, &i);
    }
  }
  /* *INDENT-ON* */
  return 0;
}

static clib_error_t *jxt_close_session_out_fn (vlib_main_t *vm,
                                                 unformat_input_t *input,
                                                 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t out_addr, ext_addr, in_addr;
  u32 out_port, ext_port;
  snat_det_map_t *mp;
  snat_det_session_t *ses;
  snat_det_out_key_t key;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d %U:%d", unformat_ip4_address, &out_addr,
                    &out_port, unformat_ip4_address, &ext_addr, &ext_port))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unformat_free (line_input);

  mp = snat_det_map_by_out (&out_addr);
  if (!mp)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_reverse (mp, &ext_addr, (u16)out_port, &in_addr);
      key.ext_host_addr = out_addr;
      key.ext_host_port = ntohs ((u16)ext_port);
      key.out_port = ntohs ((u16)out_port);
      ses = snat_det_get_ses_by_out (mp, &out_addr, key.as_u64);
      if (!ses)
        vlib_cli_output (vm, "no match");
      else
        snat_det_ses_close (mp, ses);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *jxt_close_session_in_fn (vlib_main_t *vm,
                                                unformat_input_t *input,
                                                vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, ext_addr;
  u32 in_port, ext_port;
  snat_det_map_t *mp;
  snat_det_session_t *ses;
  snat_det_out_key_t key;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d %U:%d", unformat_ip4_address, &in_addr,
                    &in_port, unformat_ip4_address, &ext_addr, &ext_port))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unformat_free (line_input);

  mp = snat_det_map_by_user (&in_addr);
  if (!mp)
    vlib_cli_output (vm, "no match");
  else
    {
      key.ext_host_addr = ext_addr;
      key.ext_host_port = ntohs ((u16)ext_port);
      ses = snat_det_find_ses_by_in (mp, &in_addr, ntohs ((u16)in_port), key);
      if (!ses)
        vlib_cli_output (vm, "no match");
      else
        snat_det_ses_close (mp, ses);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *jxt_set_timeouts_command_fn (vlib_main_t *vm,
                                                    unformat_input_t *input,
                                                    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  nat_timeouts_t timeouts = {0};
  clib_error_t *error = 0;
  u8 reset = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "udp %u", &timeouts.udp))
        ;
      else if (unformat (line_input, "tcp established %u",
                         &timeouts.tcp.established))
        ;
      else if (unformat (line_input, "tcp transitory %u",
                         &timeouts.tcp.transitory))
        ;
      else if (unformat (line_input, "icmp %u", &timeouts.icmp))
        ;
      else if (unformat (line_input, "reset"))
        reset = 1;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  if (!reset)
    {
      if (jxt_set_timeouts (&timeouts))
        {
          error = clib_error_return (0, "error configuring timeouts");
        }
    }
  else
    jxt_reset_timeouts ();
done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *jxt_show_timeouts_command_fn (vlib_main_t *vm,
                                                     unformat_input_t *input,
                                                     vlib_cli_command_t *cmd)
{
  nat_timeouts_t timeouts;
  timeouts = jxt_get_timeouts ();
  vlib_cli_output (vm, "udp timeout: %dsec", timeouts.udp);
  vlib_cli_output (vm, "tcp established timeout: %dsec",
                   timeouts.tcp.established);
  vlib_cli_output (vm, "tcp transitory timeout: %dsec",
                   timeouts.tcp.transitory);
  vlib_cli_output (vm, "icmp timeout: %dsec", timeouts.icmp);
  return 0;
}

static clib_error_t *jxt_plugin_enable_disable_command_fn (
    vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 enable = 0, is_set = 0;
  clib_error_t *error = 0;
  jxt_config_t c = {0};

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!is_set && unformat (line_input, "enable"))
        {
          unformat (line_input, "inside vrf %u", &c.inside_vrf_id);
          unformat (line_input, "outside vrf %u", &c.outside_vrf_id);
          enable = 1;
        }
      else if (!is_set && unformat (line_input, "disable"))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
      is_set = 1;
    }

  if (enable)
    {
      if (jxt_plugin_enable (c))
        error = clib_error_return (0, "plugin enable failed");
    }
  else
    {
      if (jxt_plugin_disable ())
        error = clib_error_return (0, "plugin disable failed");
    }
done:
  unformat_free (line_input);
  return error;
}

typedef struct
{
  u32 sw_if_index;
  u8 is_inside;
} sw_if_indices_t;

static clib_error_t *jxt_feature_command_fn (vlib_main_t *vm,
                                               unformat_input_t *input,
                                               vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  sw_if_indices_t *sw_if_indices = 0, *p, e;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u8 is_del = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "inside %U", unformat_vnet_sw_interface, vnm,
                    &e.sw_if_index))
        {
          e.is_inside = 1;
          vec_add1 (sw_if_indices, e);
        }
      else if (unformat (line_input, "outside %U", unformat_vnet_sw_interface,
                         vnm, &e.sw_if_index))
        {
          e.is_inside = 0;
          vec_add1 (sw_if_indices, e);
        }
      else if (unformat (line_input, "del"))
        is_del = 1;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  /* *INDENT-OFF* */
  vec_foreach (p, sw_if_indices)
  {
    if (jxt_interface_add_del (p->sw_if_index, p->is_inside, is_del))
      {
        error = clib_error_return (
            0, "%s %s %U failed", is_del ? "del" : "add",
            p->is_inside ? "inside" : "outside", format_vnet_sw_if_index_name,
            vnm, p->sw_if_index);
        break;
      }
  }
  /* *INDENT-ON* */
done:
  unformat_free (line_input);
  vec_free (sw_if_indices);
  return error;
}

static clib_error_t *jxt_show_interfaces_command_fn (vlib_main_t *vm,
                                                       unformat_input_t *input,
                                                       vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  jxt_main_t *dm = &jxt_main;
  jxt_interface_t *i;
  vlib_cli_output (vm, "jxt interfaces:");
  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces)
  {
    vlib_cli_output (
        vm, " %U %s", format_vnet_sw_if_index_name, vnm, i->sw_if_index,
        (jxt_interface_is_inside (i) && jxt_interface_is_outside (i))
            ? "in out"
            : (jxt_interface_is_inside (i) ? "in" : "out"));
  }
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
/*?
 * @cliexpar
 * @cliexstart{jxt add}
 * Create bijective mapping of inside address to outside address and port range
 * pairs, with the purpose of enabling jxt to reduce logging in CGN
 * deployments.
 * To create mapping between inside network 10.0.0.0/18 and
 * outside network 1.1.1.0/30 use:
 * # vpp# jxt add in 10.0.0.0/18 out 1.1.1.0/30
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_map_command, static) = {
    .path = "jxt add",
    .short_help = "jxt add in <addr>/<plen> out <addr>/<plen> [del]",
    .function = jxt_map_command_fn,
};

/*?
 * @cliexpar
 * @cliexpstart{show jxt mappings}
 * Show jxt mappings
 * vpp# show jxt mappings
 * jxt mappings:
 *  in 10.0.0.0/24 out 1.1.1.1/32
 *   outside address sharing ratio: 256
 *   number of ports per inside host: 252
 *   sessions number: 0
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_show_mappings_command, static) = {
    .path = "show jxt mappings",
    .short_help = "show jxt mappings",
    .function = jxt_show_mappings_command_fn,
};

// my function
// 输出我的映射表
VLIB_CLI_COMMAND (jxt_show_my_mappings_command, static) = {
    .path = "show my jxt mappings",
    .short_help = "show my jxt mappings",
    .function = jxt_show_my_mappings_command_fn,
};
// };
// 打印哈希表中所有元素
VLIB_CLI_COMMAND (jxt_show_my_in_hash_command, static) = {
    .path = "show my in hash",
    .short_help = "show my in hash",
    .function = jxt_show_my_in_hash_command_fn,
};
VLIB_CLI_COMMAND (jxt_show_my_out_hash_command, static) = {
    .path = "show my out hash",
    .short_help = "show my out hash",
    .function = jxt_show_my_out_hash_command_fn,
};
// 设置映射后的网段范围



/*?
 * @cliexpar
 * @cliexstart{jxt forward}
 * Return outside address and port range from inside address for jxt.
 * To obtain outside address and port of inside host use:
 *  vpp# jxt forward 10.0.0.2
 *  1.1.1.0:<1054-1068>
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_forward_command, static) = {
    .path = "jxt forward",
    .short_help = "jxt forward <addr>",
    .function = jxt_forward_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{jxt reverse}
 * Return inside address from outside address and port for jxt.
 * To obtain inside host address from outside address and port use:
 *  #vpp jxt reverse 1.1.1.1:1276
 *  10.0.16.16
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_reverse_command, static) = {
    .path = "jxt reverse",
    .short_help = "jxt reverse <addr>:<port>",
    .function = jxt_reverse_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show jxt sessions}
 * Show jxt sessions.
 * vpp# show jxt sessions
 * jxt sessions:
 *   in 10.0.0.3:3005 out 1.1.1.2:1146 external host 172.16.1.2:3006 state:
udp-active expire: 306
 *   in 10.0.0.3:3000 out 1.1.1.2:1141 external host 172.16.1.2:3001 state:
udp-active expire: 306
 *   in 10.0.0.4:3005 out 1.1.1.2:1177 external host 172.16.1.2:3006 state:
udp-active expire: 306
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_show_sessions_command, static) = {
    .path = "show jxt sessions",
    .short_help = "show jxt sessions",
    .function = jxt_show_sessions_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{jxt close session out}
 * Close session using outside ip address and port
 * and external ip address and port, use:
 *  vpp# jxt close session out 1.1.1.1:1276 2.2.2.2:2387
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_close_sesion_out_command, static) = {
    .path = "jxt close session out",
    .short_help = "jxt close session out "
                  "<out_addr>:<out_port> <ext_addr>:<ext_port>",
    .function = jxt_close_session_out_fn,
};

/*?
 * @cliexpar
 * @cliexstart{jxt deterministic close session in}
 * Close session using inside ip address and port
 * and external ip address and port, use:
 *  vpp# jxt close session in 3.3.3.3:3487 2.2.2.2:2387
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_close_session_in_command, static) = {
    .path = "jxt close session in",
    .short_help = "jxt close session in "
                  "<in_addr>:<in_port> <ext_addr>:<ext_port>",
    .function = jxt_close_session_in_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set jxt timeout}
 * Set values of timeouts for jxt sessions (in seconds), use:
 *  vpp# set jxt timeouts udp 120 tcp established 7500 tcp transitory 250
icmp 90
 * To reset default values use:
 *  vpp# set jxt timeouts reset
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_set_timeouts_command, static) = {
    .path = "set jxt timeouts",
    .short_help = "set jxt timeouts <[udp <sec>] [tcp established <sec>] "
                  "[tcp transitory <sec>] [icmp <sec>]|reset>",
    .function = jxt_set_timeouts_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show jxt timeouts}
 * Show values of timeouts for jxt sessions.
 * vpp# show jxt timeouts
 * udp timeout: 300sec
 * tcp-established timeout: 7440sec
 * tcp-transitory timeout: 240sec
 * icmp timeout: 60sec
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_show_timeouts_command, static) = {
    .path = "show jxt timeouts",
    .short_help = "show jxt timeouts",
    .function = jxt_show_timeouts_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{jxt plugin}
 * Enable/disable jxt plugin.
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_plugin_enable_disable_command, static) = {
    .path = "jxt plugin",
    .short_help = "jxt plugin <enable [inside vrf] [outside vrf]|disable>",
    .function = jxt_plugin_enable_disable_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set interface jxt}
 * Enable/disable jxt feature on the interface.
 * To enable jxt feature with local network interface use:
 *  vpp# set interface jxt inside GigabitEthernet0/8/0
 * To enable jxt feature with external network interface use:
 *  vpp# set interface jxt outside GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_feature_command, static) = {
    .path = "set interface jxt",
    .short_help = "set interface jxt inside <intfc> outside <intfc> [del]",
    .function = jxt_feature_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show jxt interfaces}
 * Show interfaces with jxt feature.
 * vpp# show jxt interfaces
 * jxt interfaces:
 *  GigabitEthernet0/8/0 in 
 *  GigabitEthernet0/a/0 out
 * @cliexend
?*/
VLIB_CLI_COMMAND (jxt_show_interfaces_command, static) = {
    .path = "show jxt interfaces",
    .short_help = "show jxt interfaces",
    .function = jxt_show_interfaces_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
