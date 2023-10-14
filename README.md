本项目主要对 det44 模块进行性能改善，
主要解决的是源码 vpp_det44/src/plugins/nat/det44/det44_in2out.c 地址转换效率较低的问题

源码位置：vpp_det44/src/plugins/nat/det44

改进代码1位置：vpp_det44/src/plugins/nat/det44_backup

改进方法：采用哈希表，循环队列，提高映射效率

改进代码2位置：

改进方法：采用多线程和动态地址管理，可以避免数据竞争，以及方便地址上下线

###############################################################################

源码in2out思路：（括号内为对应的文件和代码行数）
1.首先检查TTL是否为1以及是否是icmp(./det44_in2out.c: 849-873)

2.根据源ip查找映射表，没找到则丢弃(./det44_in2out.c: 876-887)，
    这一部分就是判断这个源ip是不是属于内网地址池
    
3.根据内部端口计算相对于所属映射表起始位置的内网地址的偏移量，
    并根据这个偏移量计算外网地址new_addr和起始端口lo_port(./det44_in2out.c: 889-896)
    
4.根据源目ip，源目端口查找会话(./det44_in2out.c: 898-899)，计算偏移量，获取会话信息，
    然后比较其中的源目ip和源目端口，如果找到这个会话就返回该会话
    
5.没找到会话则创建会话(./det44_in2out.c: 902-982)
    循环，找到一个


由此可见，源码中nat模块采用的是分级映射和遍历的思想。
即先找到对应的网段，再通过找对应的外部地址，再通过遍历找可用的外部端口。
并且在这个流第二次来的查找会话的时候仍然采用的遍历方式，效率较低。

#################################################################################

一、0824，改进代码1：采用哈希表，第一次新建会话采用遍历，但是后面再来的时候就直接查找哈希表，可以提升效率。

数据结构：
det_main：my_user[8k] 

    my_user：in_addr，out_addr，out_port_start，sess_nums，my_sess_index_by_in[64k]，my_sess[2k] 
    
        my_sess_index_by_in：(u16) index 
        
        my_sess：in_port，expire，state 
        

改进in2out思路：
1、根据in_addr查找in_hash_table。 
2、若能查到，则获得 in_addr 对应数据结构my_user的索引user_idx。转到步骤4。  
3、若不能查到，遍历用户数据结构my_user，找到一个 sess_nums=0 的my_user填入in_addr： 
    det_main中维护一个last_user_index的索引，表示上一次 创建 用户结构的索引 
    每次新来的查不到 in_hash 的 in_addr 就从 last_user_index 开始遍历， 
    找到一个 sess_nums=0 的用户结构（空用户，或者有用户，但是没有会话），更新其中的 in_addr，并添加哈希 
        若哈希表已满，删掉原来的哈希条目，再添加 
        若哈希表未满，添加 
    若遍历完了，还没找到则报错 
4、通过该索引i获得该in_addr对应的数据结构my_user[user_idx]。获取其中的 out_addr 
5、通过该数据结构中的会话索引数组 my_sess_index_by_in，将数据包中的 in_port 作为索引， 
    查找会话索引 ses_idx = my_sess_index_by_in[in_port]。 
6、若ses_idx为有效值，说明已经存在会话信息，但还不确定是否为该in_port的会话，以及是否超时。转到步骤8。 
    （因为in_port可以从64k个里面随机一个，但是out_port的范围只有2k，意味着32个in_port会对应一个out_port， 
    这时候就要判断拿到会话中的in_port是不是这次数据包的in_port）
7、若 ses_idx 为合法值（!= 0xFFFF，因为总共只有2k个会话），且会话数据结构my_sess[ses_idx]中的端口等于in_port，且未超时，则使用该会话即可
8、除此之外，都需要新创建会话信息（ses_idx非法，或者合法但是会话端口不等于in_port，或者超时），
    从上一次创建会话的索引开始，遍历下一个会话，若该会话端口为0或超时，使用，并更新会话信息，即my_sess[i0].in_port 和 expire 
9、此时已经拿到一个有效会话及其索引ses_idx，更新 my_sess_index_by_in[in_port] 对应的索引（方便下次来的时候直接找到这个会话） 
    则out_port = lo_port + ses_idx （out_port 和 每个sess 是一一对应关系）。 

out2in思路：
1、根据out_addr以及 out_port_index_by_out_addr = (out_port - 1024) % 2048 （即0或1） 查找out_hash_table。 
2、若能查到，获取my_user的索引user_index。转到步骤4. 
3、若不能查到，丢弃该数据包。 
4、通过该索引user_index获得对应的数据结构my_user[user_index]，从中获得in_addr。 
5、根据dst_addr（即out_addr），计算会话索引 ses_idx = out_port - lo_port 
6、根据 ses_idx 得到对应的会话 my_sess[ses_idx]，判断是否超时 
7、若超时，丢弃数据包。若未超时，获取其中的in_port。

存在问题：
 
我的想法是既然这个会话非法就使用这个会话，而不是从上一次创建的会话地方开始遍历，
这会导致每次创建会话都是跳来跳去的，这如果有二层nat，这会导致仍然使用第一层nat后的端口，
如果是同一个用户的话，对于回来的包是不知道用户侧其实是换了一个in_port的。

##################################################################################

一、0901，改进代码2：增加动态地址管理，采用多线程。实现动态添加内外地址池，动态选择映射出口和端口。

主要思想：
1、多个线程，每个线程负责一部分独有的out_addr，这样不会出现数据竞争，因为不这么做，不同的线程可能对同一个out_addr下的信息修改。而不是采用锁，因为锁的效率很低，开销很大。

2、每个线程对五元组进行负载，采用哈希的方式将同一个流映射到同一个out_addr和out_port上。而不是采用用户遍历和会话遍历，提升效率

3、对于新的流，采用循环队列的方式查找合法出口和端口，并在查找过程中进行超时判断，从而老化会话，而不是采用定期主动清理会话，这提升了效率，降低开销

4、采用 in2out_hash 和 out2in_hash，使得回来的流可以直接通过out_addr 和 out2in_hash 直接查到对应的线程和地址位置索引，再通过out_port 和 sess 的对应关系，就可以直接拿到会话信息，这样避免了回溯过程中多次遍历，提升效率

5、提供了 添加、删除 内网地址的接口，可以在控制面进行操作，而不是在数据面，提高了数据包处理效率

大概流程：
Inout：
1、通过in_addr查找 in_addr_hash，若没找到，丢弃。
2、获取线程索引 thread_id，根据 in_addr 和 in_port 通过哈希拿到一个下标索引 out_addr_idx 和 ses_idx，这样就拿到了out_addr 这个数据结构，以及下面的会话信息。
3、若查不到，说明是新的流，创建
    若找到的 out_addr 中的地址值为非法（out_addr下线）：选择out_addr，选择out_port
选择out_addr：从上一次选择的位置开始循环遍历，若 out_addr 值为非法值，使用。
    若找到 out_addr ，但找到的 ses 非法（端口为0或超时）：选择out_port
判断ses_num是否小于64k，若大于等于，重新选择out_addr。
选择out_port：从上一次创建会话的位置遍历 out_addr 这个结构下面的会话数组，找到一个 out_port=0 或超时的会话，使用，得到out_port，
添加 in2out_hash：in_addr+in_port到 out_addr_idx 和 ses_idx 的哈希条目，针对超时的情况，删除原本会话存储信息中in_addr+in_port 到这个地址和会话索引的哈希条目，这样才能正常老化会话信息。
添加out2in_hash：添加 out_addr 到 thread_idx 和 out_addr_idx  的哈希条目，方便out2in。

out2in：
1、通过 out_addr 查找 thread_idx 和 out_addr_idx，若没有找到，丢弃，若找到，根据拿到的out_addr结构，在其中根据out_port拿到对应会话，判断是否超时，超时则丢弃
8k个用户
4k个out_addr

数据结构：
det_main：
内网地址池哈希：in_addr_hash
从外到内哈希：in2out_hash，
从外到内哈希：out2in_hash，
上一次分配地址给时的线程的索引 last_thread_idx，
不同线程下的out_addr池，每个是 my_out 类型：address_pools[thread_id][out_addr_idx]，
每个线程上一次选择地址的索引：last_addr_select_idx[thread_nums]，
每个线程上一次添加地址的索引：last_addr_add_idx[thread_nums]，
    my_out：out_addr，last_port_idx，my_sess[64k]，out_port_start，sess_nums， 
        my_sess：in_addr，in_port，expire，state

添加地址池：
需要手动添加外部地址池 和 内部地址池：添加 jxt add in <in_addr>， jxt add out <out_addr>两个接口。
jxt add in <in_addr>：添加 in_addr_hash 哈希条目。
jxt add out <out_addr>：
记录last_thread_idx，表示当前应该将这个out_addr分配给哪个线程，这样每个线程会维护一个自己的地址池
得到上一次在该线程上添加地址的索引： add_idx0= last_addr_add_idx[last_thread_idx] ，从 address_pools[last_thread_idx][add_idx0]] 开始遍历，若其中out_addr为'-1'，即非法值，将值置为新的out_addr值
添加out2in_hash：添加该 out_addr 到 thread_idx 和 out_addr_idx 的哈希条目，方便out2in。

删除out_addr：
根据从外到内的哈希 out2in_hash，通过 out_addr 找到线程索引thread_idx，和在该线程地址池上的位置out_addr_idx。
将 out0 = address_pools[thread_idx][out_addr_idx] 中的out_addr值置为非法值，表示删除该地址，将其下会话信息清零。同时删除out2in_hash 中对应的哈希条目

删除in_addr：
遍历 in_addr 下的每一个in_port，对于每一组 in_addr+in_port，删除 in2out_hash中相应条目，删除in_addr_hash 哈希条目，这样就可以使得该in_addr下线。

选择地址：
根据thread_id，得到上一次选择地址的位置索引 select_idx0=last_addr_select_idx[thread_id]，
则从address_pools[thread_idx][select_idx0] 开始遍历，若其中out_addr为'-1'，即非法值，跳过。若为合法值，选择使用，获取其中 last_port_idx 等信息


##################################################################################

Vector Packet Processing
========================

## Introduction

The VPP platform is an extensible framework that provides out-of-the-box
production quality switch/router functionality. It is the open source version
of Cisco's Vector Packet Processing (VPP) technology: a high performance,
packet-processing stack that can run on commodity CPUs.

The benefits of this implementation of VPP are its high performance, proven
technology, its modularity and flexibility, and rich feature set.

For more information on VPP and its features please visit the
[FD.io website](http://fd.io/) and
[What is VPP?](https://wiki.fd.io/view/VPP/What_is_VPP%3F) pages.


## Changes

Details of the changes leading up to this version of VPP can be found under
@ref release_notes.


## Directory layout

| Directory name         | Description                                 |
| ---------------------- | ------------------------------------------- |
|      build-data        | Build metadata                              |
|      build-root        | Build output directory                      |
|      doxygen           | Documentation generator configuration       |
|      dpdk              | DPDK patches and build infrastructure       |
| @ref extras/libmemif   | Client library for memif                    |
| @ref src/examples      | VPP example code                            |
| @ref src/plugins       | VPP bundled plugins directory               |
| @ref src/svm           | Shared virtual memory allocation library    |
|      src/tests         | Standalone tests (not part of test harness) |
|      src/vat           | VPP API test program                        |
| @ref src/vlib          | VPP application library                     |
| @ref src/vlibapi       | VPP API library                             |
| @ref src/vlibmemory    | VPP Memory management                       |
| @ref src/vnet          | VPP networking                              |
| @ref src/vpp           | VPP application                             |
| @ref src/vpp-api       | VPP application API bindings                |
| @ref src/vppinfra      | VPP core library                            |
| @ref src/vpp/api       | Not-yet-relocated API bindings              |
|      test              | Unit tests and Python test harness          |

## Getting started

In general anyone interested in building, developing or running VPP should
consult the [VPP wiki](https://wiki.fd.io/view/VPP) for more complete
documentation.

In particular, readers are recommended to take a look at [Pulling, Building,
Running, Hacking, Pushing](https://wiki.fd.io/view/VPP/Pulling,_Building,_Run
ning,_Hacking_and_Pushing_VPP_Code) which provides extensive step-by-step
coverage of the topic.

For the impatient, some salient information is distilled below.


### Quick-start: On an existing Linux host

To install system dependencies, build VPP and then install it, simply run the
build script. This should be performed a non-privileged user with `sudo`
access from the project base directory:

    ./extras/vagrant/build.sh

If you want a more fine-grained approach because you intend to do some
development work, the `Makefile` in the root directory of the source tree
provides several convenience shortcuts as `make` targets that may be of
interest. To see the available targets run:

    make


### Quick-start: Vagrant

The directory `extras/vagrant` contains a `VagrantFile` and supporting
scripts to bootstrap a working VPP inside a Vagrant-managed Virtual Machine.
This VM can then be used to test concepts with VPP or as a development
platform to extend VPP. Some obvious caveats apply when using a VM for VPP
since its performance will never match that of bare metal; if your work is
timing or performance sensitive, consider using bare metal in addition or
instead of the VM.

For this to work you will need a working installation of Vagrant. Instructions
for this can be found [on the Setting up Vagrant wiki page]
(https://wiki.fd.io/view/DEV/Setting_Up_Vagrant).


## More information

Several modules provide documentation, see @subpage user_doc for more
end-user-oriented information. Also see @subpage dev_doc for developer notes.

Visit the [VPP wiki](https://wiki.fd.io/view/VPP) for details on more
advanced building strategies and other development notes.


## Test Framework

There is PyDoc generated documentation available for the VPP test framework.
See @ref test_framework_doc for details.
