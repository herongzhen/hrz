# **ndpi的使用介绍**
nDPI是一个从OpenDPI发展而来的DPI库，现在由ntop组织负责维护。
## 一 .特点
1. 支持流量的大小监控
2. 支持两百多种的协议的解析
3. 能够定义端口或端口范围来匹配协议
4. 能够根据字符串匹配子协议
5. nDPI实现了线程安全
6. 实现了加密流量的解析
## 二.主要功能
 1.核心库用于处理数据包抽取基本信息
 2.解析器用插件的方式实现，用于解析报文检测的协议类别
## 三.nDPI的安装
i. 编译
./autogen.sh
./configure
make<br>
ii. 测试
cd tests/
./do.sh<br>
iii. 安装
make install (需要root权限）<br>
iv.例子工具
在example中有一个已经编译好的例子ndpiReader
输入： ./ndpiReader -h 可以查看关于ndpi使用命令行时的一些参数的解析

Usage:<br>
 i<file.pcap|device>  |指定一个需要被识别的pcap文件/文件列表，或者需要被嗅探的设备接口/接口列表(文件列表或接口列表使用","作为分隔符)<br> 
 -f<BPF filter>         |指定一条BPF规则的过滤字串<br>
 -s<duration>           |最大的嗅探时间(显然只在嗅探接口时生效)<br>
 -m<duration>           | pcap文件分段解析超时时间(显然只在解析pcap文件时生效)<br>
 -p<file>.protos        |指定一个自定义的协议识别配置文件(eg.protos.txt)<br>
 -l<num loops>          |指定循环执行嗅探的次数(仅用于测试)<br>
 -n<num threads>        |指定线程数量，缺省跟设备接口数量对应                     |如果传入的是pcap文件时固定使用单线程<br>
 -j<file.json>          |指定一个输出包内容的json文件<br>
 -g<id:id...>           |指定线程-CPU亲和关系映射表<br>
 -d                     |禁止协议猜测功能<br>
 -q                     |安静模式，意味着不打印信息<br>
 -t                     |解析GTP隧道协议<br>
 -r                     |打印 nDPI版本和git版本<br>
 -w<path>               |指定测试信息的输出文件<br>
 -h                     | help信息<br>
 -v<1|2|3>              |按级别进一步打印包的详细信息，分为1、2、3级<br>

## 四.ndpi的使用

### 1. ndpi协议识别总体概述

**结构初始化** &nbsp;ndpi_workflow_init<br>
**协议模块加载**&nbsp;ndpi_init_protocol_defaults<br>
**协议识别算法注册**&nbsp; ndpi_set_protocol_detection_bitmask2<br>
**进行协议识别,流量分类**&nbsp;ndpi_detection_process_packet<br>
**针对未能识别的协议进行协议猜测** &nbsp;ndpi_guess_protocol_id<br>
**产生协议识别结果,记录在结构体中**&nbsp; ndpi_flow_struct<br>

###  2.ndpi的工作流程

&nbsp;&nbsp;首先是程序的初始化，调用setupDetection()函数.
&nbsp;&nbsp;接下来会开启线程调用libpcap库函数对通过电脑网卡的数据包进行抓取，或者读取传入的.pcap文件. 
&nbsp;&nbsp;接下来对每一个数据包（数据包(packet)和数据流(flow)，一个数据流中可能会有很多个数据包，就像我们申请一个网页请求，由于页面信息很大，所以会分成很多个数据包来传输，但这些数据包同属于一个数据流），首先对其数据链路层和IP层进行拆包分析pcap_packet_callback()函数，判断是否为基于IP协议等，并获得其源目的IP、协议类型等。 
在接下来调用packet_processing()函数，进行传输层分析。在进行传输层分析时调用了get_ndpi_flow()函数，该函数返回ndpi_flow这个结构体。在get_ndpi_flow()函数中获取传输层的信息如源目的端口等信息。然后根据（源目的IP、源目的端口、协议类型(tcp\udp)）这五个元素计算出idx。

    idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
    ret = ndpi_tfind(&flow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp);
程序维护了一个数组，用来记录所有的数据流，而idx是用来标识不同的数据流，根据前面解析出数据包的五元组计算idx，然后查询 ndpi_flows_root[]这个数组在索引为idx位置是否已经有了记录。一般，对于一个数据流而言，该流的第一个数据包查询时ndpi_flows_root[idx]为空，则建立一个新的ndpi_flow对象并保存到该位置处；等抓到该数据流的后续数据包时，因为属于同一个流(即idx相同)，所以ndpi_flows_root[idx]不为空，则直接返回已经有的ndpi_flow即可。至此，我们得到了ndpi_flow这个结构体.
接下来函数会调用ndpi_detection_process_packet()这个函数进行应用层分析。这也是应用协议分析的主体函数.这个函数传进的参数是ndpi_flow_struct(下面记为flow)，函数首先会对flow->packet即对packet这个结构体进行初始化。因为对于同一个流flow而言，在该结构体中有些变量在第一个数据包时已经初始化了，这些变量可能在特定情况下才会发生改变，比如检测出了协议等；而对每一个数据包，flow中必须要变的就是flow->packet中的信息。接下来会调用ndpi_connection_tracking()函数，这个函数的主要作用是判断这个包的‘位置’,这个函数在数据包重组等功能中会有很重要的作用。部分代码如下`   

    if(tcph->syn != 0 && tcph->ack == 0 && flow->l4.tcp.seen_syn == 0 && flow->l4.tcp.seen_syn_ack == 0
           && flow->l4.tcp.seen_ack == 0) {
          flow->l4.tcp.seen_syn = 1;
        }//第一次
        if(tcph->syn != 0 && tcph->ack != 0 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 0
           && flow->l4.tcp.seen_ack == 0) {
          flow->l4.tcp.seen_syn_ack = 1;
        }//第二次
        if(tcph->syn == 0 && tcph->ack == 1 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 1
           && flow->l4.tcp.seen_ack == 0) {
          flow->l4.tcp.seen_ack = 1;
        }//第三次
        //上面三句是三次握手相应的判断语句
        if((flow->next_tcp_seq_nr[0] == 0 && flow->next_tcp_seq_nr[1] == 0)
           || (proxy_enabled && (flow->next_tcp_seq_nr[0] == 0 || flow->next_tcp_seq_nr[1] == 0))) {
          if(tcph->ack != 0) {
          //packet_direction表示方向是从源IP到目的IP\从目的IP到源IP
        flow->next_tcp_seq_nr[flow->packet.packet_direction] =
          ntohl(tcph->seq) + (tcph->syn ? 1 : packet->payload_packet_len);
        if(!proxy_enabled) {
          flow->next_tcp_seq_nr[1 -flow->packet.packet_direction] = ntohl(tcph->ack_seq);
        }
          }
        } else if(packet->payload_packet_len > 0) {
          /* check tcp sequence counters */
          if(((u_int32_t)
          (ntohl(tcph->seq) -
           flow->next_tcp_seq_nr[packet->packet_direction])) >
         ndpi_struct->tcp_max_retransmission_window_size) {
        packet->tcp_retransmission = 1;
        }

   
### 3. 分析函数API的实现

ndpi内部提供供了ndpi_detection_process_packet函数作为协议检测的API,函数原型如下:


    unsigned int ndpi_detection_process_packet(
        struct ndpi_detection_module_struct *ndpi_struct,
        //在ndpi_init_detection_module函数进行初始化
        struct ndpi_flow_struct *flow,
        //用来维护当前会话的检测协议栈，以及检测的参数等
        const unsigned char *packet,
        //ip层数据报文
        const unsigned short packetlen,
        //报文长度
        const u_int32_t current_tick,
        //包的tick值
        struct ndpi_id_struct *src,struct ndpi_id_struct *dst)
        //ndpi_id_struct里面包含各个协议的源目的端信息
    
 1.检测包长度
 
  这里它通过检测包长度（packetlen），对包的可用性进行了测试。如果包长度没有20字节（ip数据报文至少20字节），则利用ndpi_int_reset_packet_protocol把flow内部的协议栈顶类型置为UNKNOW。并且清0协议栈信息字段，最后返回UNKNOW类型。
 2、flow->packet的初始化
 
     这里通过捕获的ip报文（packet参数）和用户设置的current_tick参数，对flow->packet.iph和flow->packet.tick_timestamp进行初始化。
 3、传输层检测及flow的初始化
 
     这里主要通过函数ndpi_init_packet_header（在ndpi_main.c中进行了定义）进行了实现，他完成比较多的工作。
        1）首先一个就是根据ndpi_packet_struct中的协议栈内容和描述信息，对flow的协议栈内容和描述信息进行了初始化。这部分通过内部的ndpi_apply_flow_protocol_to_packet函数进行了实现。
        2）根据ipv4和ipv6对flow中的packet分别进行初始化（flow->packet.iph和flow->packet.iphv6）
        3）通过ndpi_detection_get_l4_internal对报文的ipv4（ipv6）header进行检测，并且获取传输层协议信息。通过l4protocol变量进行传递，记录传输层协议号。
        4）根据l4protocol字段进行传输层的判别，如果是tcp（协议号是6）则对包内部的syn和ack等字段进行初步的检测。如果是udp（协议号是17），则计算出包的长度。初始化flow->packet当中的字段
  4、flow传输层信息的初始化
  
     这里主要通过报文获取传输层信息，比如在tcp协议中我们捕获到的报文是握手中的什么角色，是ack包还是其他的。这些信息将对检测提供一些数据。
        1）首先通过src和dst参数初始化flow->src和flow->dst字段
        2）通过ndpi_connection_tracking函数进行我们上述的工作。这里它判断的tcp握手的状态，并且通过flow->next_tcp_seq_nr数组对tcp序列进行了描述。

    if (tcph->syn != 0 && tcph->ack == 0 && flow->l4.tcp.seen_syn == 0 && flow->l4.tcp.seen_syn_ack == 0
    	&& flow->l4.tcp.seen_ack == 0) {
          flow->l4.tcp.seen_syn = 1;}
    if (tcph->syn != 0 && tcph->ack != 0 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 0
    	&& flow->l4.tcp.seen_ack == 0) {
          flow->l4.tcp.seen_syn_ack = 1;}
    if (tcph->syn == 0 && tcph->ack == 1 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 1
    	&& flow->l4.tcp.seen_ack == 0) {
          flow->l4.tcp.seen_ack = 1;}

ndpi中通过flow->l4.tcp中的seen_syn、seen_syn_ack和seen_ack记录tcp的握手状态。然后根据分析报文中的syn和ack字段进行归类，为后期的检测提供数据基础。

    
###  4.ndpi如何定义一个协议

ndpi中,每一个支持的协议都用一个唯一的数字和一个名称注册定义.在代码中用宏定义了所有能够支持的协议
部分代码如下:

typedef enum {
  NDPI_PROTOCOL_UNKNOWN&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=0,
  NDPI_PROTOCOL_FTP_CONTROL&nbsp;=1,
  NDPI_PROROCOL_MAIL_SMTP&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=3,
  NDPI_PROTOCOL_DNS&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=5,
  NDPI_PROTOCOL_HTTP&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=7,
  NDPI_PROTOCOL_SSDP&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=12,
  NDPI_PROTOCOL_QQ&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=48,
  NDPI_PROTOCOL_MSN&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=68,
  NDPI_PROTOCOL_SINA&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=200,
  }
  具体完整代码可在nDPI/src/include/ndpi_protocol_ids.h中查看.

### 5.ndpi解析流的流程

1.高层应用把三,四层的数据交给nDPI;
2.nDPI根据,默认端口和承载协议尝试猜测应用协议,并使用猜出来的协议解析器按顺序尝试就解析,如果解析成功,返回结果.如果不成功,就进行下一步.
3.根据承载协议使用该承载协议分类下的全部协议解析其按顺序尝试解析(比如流是基于TCP,就用和TCP有关的解析器解析,而不会考虑UDP),如果成功,返回结果,不成功,就下一步.
4.上一部不成功的原因可能是协议不被支持或者没有抓到关键的包,如果协议不被支持就会停止解析,如果是后面一种情况就继续等待高层应用提供新的数据(出现这种情况的主要原因是流开始了但没有抓到前面的关键的包,从而导致识别失败)
如何才能知道纳西哪些包重要?哪些包不重要?
流使用不同的承载协议还有某些软件在开始传输数据之前会进行协商或者其他的处理,这些都是可以作为参照的流量特征.影响DPI引擎的性能的因素主要是支持的协议数量和流元数据的抽取,因为在识别的流程中,nDPI先根据端口或者url猜测可能的协议种类并解析器尝试解析,如果猜测不对就按照解析器的注册顺序解析直到有一个解析成功;
完成分析
调用完ndpi_detection_process_packet函数后我们需要检查返回值,如果不等于NDPI_PROTOCOL_UNKNOWN就证明找到了协议类型.
### 6.ndpi中重要的函数结构

#### 1.ndpi_detection_module_struct

主要用于存储一些全局变量,由ndpi_init_detection_module()函数在初始化的过程中返回.结构体定义如下:

typedef struct ndpi_detection_module_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK generic_http_packet_bitmask;
//回调数组，当检测协议时会逐个进行遍历，调用相应协议检测函数。这是总的，下面又分为tcp/udp
  struct ndpi_call_function_struct callback_buffer[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size;//=150，下面数字也都是调试过程中得到，可能不同版本支持协议数不同
//基于tcp协议且不带负载，共有11种
  struct ndpi_call_function_struct callback_buffer_tcp_no_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_tcp_no_payload;
//基于tcp且带负载协议的应用，共113种
  struct ndpi_call_function_struct callback_buffer_tcp_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_tcp_payload;
//基于udp协议的应用，共73种
  struct ndpi_call_function_struct callback_buffer_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_udp;
//既不是基于tcp也不是基于udp协议类型，共10种；
  struct ndpi_call_function_struct callback_buffer_non_tcp_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_non_tcp_udp;
//该结构体下面进行介绍，之后会构成二叉树，根据端口进行查找；
  ndpi_default_ports_tree_node_t *tcpRoot, *udpRoot;
  u_int32_t tcp_max_retransmission_window_size;
  /* IP-based protocol detection */
  void *protocols_ptree;
//不同协议所对应的端口信息  
  ndpi_proto_defaults_t proto_defaults[NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS];

  u_int8_t match_dns_host_names:1, http_dissect_response:1;
  u_int8_t direction_detect_disable:1; /* disable internal detection of packet direction */
} ndpi_detection_module_struct_t;

#### 2.ndpi_packet_struct

    这个结构体主要用于存储一个数据包的相关信息
        typedef struct ndpi_packet_struct {
      const struct ndpi_iphdr *iph;//ip层信息
    #ifdef NDPI_DETECTION_SUPPORT_IPV6
      const struct ndpi_ipv6hdr *iphv6;
    #endif
      const struct ndpi_tcphdr *tcp;//tcp协议头
      const struct ndpi_udphdr *udp;//udp协议头
      const u_int8_t *generic_l4_ptr;   /* is set only for non tcp-udp traffic */
      const u_int8_t *payload;//负载。数据包再除去数据链路层信息后，接下来是ip层信息，在接下来是传输层信息，即tcp/udp/generic_l4_ptr,再接下来就是负载信息。
      u_int16_t detected_protocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
      u_int8_t detected_subprotocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
    //接下来是有关http协议的一些变量定义，不全部列出
      struct ndpi_int_one_line_struct line[NDPI_MAX_PARSE_LINES_PER_PACKET];
      struct ndpi_int_one_line_struct host_line;
    ......
    //这里是数据包各层信息（长度，字节数，协议等等）
      u_int16_t l3_packet_len;  u_int16_t l4_packet_len;
      u_int16_t payload_packet_len;  u_int16_t actual_payload_len;
      u_int16_t num_retried_bytes;  u_int16_t parsed_lines;
      u_int16_t parsed_unix_lines;  u_int16_t empty_line_position;
      u_int8_t tcp_retransmission;  u_int8_t l4_protocol;
      u_int8_t ssl_certificate_detected:4, ssl_certificate_num_checks:4;
      u_int8_t packet_lines_parsed_complete:1,    packet_direction:1,//源到目的、目的到源
        empty_line_position_set:1;
    } ndpi_packet_struct_t;
#### 3.ndpi_flow_struct

这个结构体用于存储一个数据流的相关信息,一个数据流可能会有很多数据包.所以在这个结构体中定义了很多标识变量(有出生初始赋值),用于区别不同的数据包和减少重复多余的工作

    typedef struct ndpi_flow_struct {
      u_int16_t detected_protocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
      u_int16_t guessed_protocol_id;
    
      u_int8_t protocol_id_already_guessed:1;
      u_int8_t no_cache_protocol:1;
      u_int8_t init_finished:1;
      u_int8_t setup_packet_direction:1;
      u_int8_t packet_direction:1; /* if ndpi_struct->direction_detect_disable == 1 */
      /* tcp sequence number connection tracking */
      u_int32_t next_tcp_seq_nr[2];
    //http协议相关信息
      struct {
        ndpi_http_method method;      
        char *url, *content_type;
      } http;
    
      union {
        struct {
          u_int8_t num_queries, num_answers, ret_code;
          u_int8_t bad_packet /* the received packet looks bad */;
          u_int16_t query_type, query_class, rsp_type; 
        } dns;
    
        struct {
          char client_certificate[48], server_certificate[48];
        } ssl;
      } protos;
    
      NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
    
      /* internal structures to save functions calls */
      struct ndpi_packet_struct packet;
      struct ndpi_flow_struct *flow;
      struct ndpi_id_struct *src;
      struct ndpi_id_struct *dst;
    } ndpi_flow_struct_t;

#### 4.ndpi_set_protocol_detection_bitmask2

##### 1.NDPI_PROTOCOL_BITMASK all

这里的NDPI_PROTOCOL_BITMASK代表的是一个变量类型,而all则是一个定义的实例(变量),详细定义,如下

    typedef u_int32_t ndpi_ndpi_mask;
    typedef struct ndpi_protocol_bitmask_struct {
      ndpi_ndpi_mask  fds_bits[NDPI_NUM_FDS_BITS];
    } ndpi_protocol_bitmask_struct_t;
    #define NDPI_PROTOCOL_BITMASK ndpi_protocol_bitmask_struct_t

其实NDPI_PROTOCOL_BITMASK类型就是一个u_int_32_t的数组.
数组的大小NDPI_FDS_BITS计算过程:

    #define NDPI_NUM_BITS              256  //这个是ndpi现阶段支持的协议数
    #define NDPI_BITS /* 32 */ (sizeof(ndpi_ndpi_mask) * 8 /* number of bits in a byte */)        /* bits per mask */
    #define howmanybits(x, y)   (((x)+((y)-1))/(y))
    #define NDPI_NUM_FDS_BITS     howmanybits(NDPI_NUM_BITS, NDPI_BITS)
具体详细代码在nDPI/src/include/ndpi_define.h中
 在这里提出一个问题:(((x)+((y)-1))/(y))是如何计算的?
 
   这里维护协议映射的数据结构是上面提到的ndpi_protocol_bitmask_struct（u_int32_t的数组）。对于数组的每一个位置比如fds_bits[1]，这u_int32_t一共有4字节。也就事32位，每位代表这一个协议的映射。这一点不仅可以从上面的定义看出，在接下来的第2部分将更明显地可以看到这是一个类似hash的映射结构。然后回到为什么要(((x)+((y)-1))/(y))的问题，这里的y其实就是32，所以这里这样计算数组是为了得出一个恰好满足能存放协议映射的数组大小（当然数组的位数不是全部应用与映射，毕竟会有一点空间的浪费）

##### 2.NDPI_BITMASK_SET_ALL(all)

   这个宏定义的作用是把映射中的所有应用都进行设置

    #define NDPI_SET(p, n)    ((p)->fds_bits[(n)/NDPI_BITS] |= (1 << (((u_int32_t)n) % NDPI_BITS)))
    //这里通过|=操作进行设置，原理和+=一样只是换成逻辑符。然后从后面的操作我们可以明显看到hash的身影
    #define NDPI_CLR(p, n)    ((p)->fds_bits[(n)/NDPI_BITS] &= ~(1 << (((u_int32_t)n) % NDPI_BITS)))
    //首先通过n/NDPI_BITS在数组上进行定位，然后通过n%NDPI_BITS在4个字节的32位上进行定位。下面同理
    #define NDPI_ISSET(p, n)  ((p)->fds_bits[(n)/NDPI_BITS] & (1 << (((u_int32_t)n) % NDPI_BITS)))
    #define NDPI_ZERO(p)      memset((char *)(p), 0, sizeof(*(p)))
    #define NDPI_ONE(p)       memset((char *)(p), 0xFF, sizeof(*(p)))
    //下面对原始宏进行了再封装
    #define NDPI_BITMASK_ADD(a,b)     NDPI_SET(&a,b)
    #define NDPI_BITMASK_DEL(a,b)     NDPI_CLR(&a,b)
    #define NDPI_BITMASK_RESET(a)     NDPI_ZERO(&a)  //在ndpi_init_detection_module的协议初始化中使用
    #define NDPI_BITMASK_SET_ALL(a)   NDPI_ONE(&a)
    #define NDPI_BITMASK_SET(a, b)    { memcpy(&a, &b, sizeof(NDPI_PROTOCOL_BITMASK)); }
    //下面的定义也是根据第一部分的原始宏进行的封装，将在下面即将讲到的ndpi_set_protocol_detection_bitmask2函数中被大量使用
    #define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value)     NDPI_SET(&bmask,value)
    #define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value)   NDPI_CLR(&bmask,value)
    #define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value) NDPI_ISSET(&bmask,value)
    #define NDPI_SAVE_AS_BITMASK(bmask,value)  { NDPI_ZERO(&bmask) ; NDPI_ADD_PROTOCOL_TO_BITMASK(bmask, value); }

##### 3.ndpi_set_detection_bitmask2(ndpi_struct,&all)
   
   这一部分是检测协议注册的核心函数,其中掺杂着一些协议之间的依赖关系,列举部分代码段研究其具体的工作原理
   
       #ifdef NDPI_PROTOCOL_SNMP //SNMP是一个网络管理协议
         if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(*detection_bitmask, NDPI_PROTOCOL_SNMP) != 0) {
	         //我们在上面第2点中介绍了NDPI_COMPARE_PROTOCOL_TO_BITMASK的具体实现，如果我们有注册这个协议进入if语句里面
	         ndpi_struct->callback_buffer[a].func = ndpi_search_snmp;
		         //这一步是非常核心的，它为SNMP协议注册了检测函数ndpi_search_snmp。这里的callback_buffer是在ndpi_detection_module_struct结构体中定义
		         ndpi_struct->callback_buffer[a].ndpi_selection_bitmask = NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
			     
			         NDPI_SAVE_AS_BITMASK(ndpi_struct->callback_buffer[a].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);
				         //这里是把原来的detection_bitmask表清空。并注册NDPI_PROTOCOL_UNKNOWN。
				         //但是这里需要主要的是callback_buffer[a]，所以这个清空的映射表是针对SNMP协议，而不是全部协议的映射记录表
				         NDPI_SAVE_AS_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_PROTOCOL_SNMP);
					         //同理，这里清空excluded_protocol_bitmask映射表，并注册NDPI_PROTOCOL_SNMP协议
					         a++;//next
						       }
    #endif
