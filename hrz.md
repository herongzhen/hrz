# ntopng的使用

ntopng是基于高速网络的流量分析和流量收集，是对网络流量实时监控显示的一款工具。
## 1. ntopng 的安装
在已经编写好的Dcokerfile、startup.sh文件所在的目录下运行命令
>docker build -t ntop .

>docker run -ti --privileged ntop -p 23000:3000

运行完成后，在浏览器的地址栏中输入 localhost:23000,可以进入到ntopng的web界面。

## 2. web界面
首先出现的是登录界面，默认的用户名是admin,密码admin
成功登录以后，在页面的最上面一栏是ntopng的标题栏，每个按钮有不同的功能，分别是：Home(关于ntopng的介绍）、Dashboard(扇形图）、Alerts(警告）、Flows(流）、Hosts(主机）、Interfaces(接口）、设置、LogoutAdmin、主机搜索框。

在最底部有很多的参数，左边参数是登录的用户、监控的接口和使用的版本;中间显示的是一个为监控接口提供的带宽饱和水平的衡量标准;右边的分别是正常的运行时间信息、Host、device和flows(ntop当前监视的流的总数）。

## 3. 标题栏
### 3.1 Home
home栏共有七个子选项，分别是：About ntopng、Runtime Status、ntop Blog、Help and News、Report an Issue、User’s Guide、Lua/C API。
#### 3.1.1 About ntopng
显示ntopng的版本、平台等相关的细节的信息。
#### 3.1.2 Runtime Status
显示ntopng的运行状态，包含系统ID、CPU负载、版本号、主机系统信息、进程ID、最后的日志追踪等信息。
#### 3.1.3 ntop Blog
是一个指向http：//www.ntop.org/byq/page页面的链接，在这里你可以找到一些有用的信息。
### 3.2 Dashboard
Dashboard是一个动态页面，它为ntopng监视的所选接口或接口视图提供当前流量的更新。
在DashBoard的页面中，有六个子选项： Talkers、Hosts、Ports、Protocols、ASNs、Senders
#### 3.2.1 Talkers
此页面显示了当前活动在监视的接口上的hosts。hosts通过有色条（表示流动）连接在一起。客户端主机总是放置在有色条的左侧边缘。而服务器端则放在右侧。有色条的宽度与交换的流量成正比，宽度越大，对应的主机对之间交换的流量就越高。
在底部的中心显示了两个选项：Refreshfrenquence、Liveupdate,分别表示刷新的频率以及实时更新，默认的刷新频率是五秒，它的值可以在下拉菜单中设置，实时更新选项可以暂停。
双击任何主机名都会转到“主机详情信息”页面，该界面介绍了host相关信息。类似的，双击表示流的任意一个流动条都会跳转到“主机比较”页面。主机也可以成对地进行比较，可以看到它们的行为和趋势。
#### 3.2.2 Hosts
此页面用扇形图来表示所捕获的流量。双击任何一个主机名（或者是未解析的IP地址）可以访问到相应的“主机详情信息”页面。
聚合产生的扇形图是进行实时更新的。
#### 3.2.3 Ports
此页面显示了两个单独的扇形图，最常用的端口是客户端和服务器端。每一个扇形图分别提供客户端端口和服务器端端口的统计信息。可以双击显示的端口号，访问到“Active Flows”页面中，该页面列出是当前所有活跃的流。
#### 3.2.4 Protocols
此页面使用一个扇形图表示每一个应用协议划分的带宽。通过NDPI引擎来进行协议识别。无法识别协议被标记为Unkown。
可以单击协议名称，访问到关于该协议的更详细的界面.
#### 3.2.5 ASNs
ASNs表示的是自治系统
此页面将有自治系统（AS)分组的项目用一个扇形图来表示。
#### 3.2.6 Senders
此页面将当前活动的top流发送器用一个扇形图表示。该图显示了本地或远程网络上的端点发送的业务所占百分比。

### 3.3 Flows
Flows通过五元组进行唯一地识别
>Source IP address
>destination IP address

>Source Port 
>destination port

>Layer-4 protocol

流表中有多个信息字段：Application（应用程序）、Layer-4 Protocol(第四层协议）、Client(客户端）、Sever hosts(服务器主机）、Duration(持续时间）、Breakdown(客户端和服务器故障）、ActualThpt(实时传输速率）、Total Bytes(总字节）、Additional Information(附加信息）。
#### 3.3.1 Application
应用程序检测失败的情况下，ntopng将流程标记为“UnKnown”,如果检测成功，若应用程序被认为是好的（坏的），显示应用程序名称和拇指向上（向下）。
可以单击应用程序名称，查看应用程序生成的所有流量信息。
#### 3.3.2 Layer-4 Pro
Layer-4协议是在传输层中使用的协议。最常见的传输协议是可靠的传输控制协议（TCP）和用户数据报协议（UDP)。
#### 3.3.3 Client
包含了关于流的客户端端点的主机和端口信息。如果主机是流的发起方，那么就将其视为客户端。显示的格式是“host：port"。
#### 3.3.4 Server
包含了有关流的服务器端点的信息。如果主机不是流的发起方，就将其视为服务器。
#### 3.3.5 Duration
这是一个数值，它表示的是从客户端打开流以后所经历的时间。
#### 3.3.6 Breakdown
此选项显示一个业务流条，流量是双向的，业务流既能从服务器端流向客户端，也从客户端流向服务器端，它表示两个方向的交换量。客户端到服务器端显示为橙色，服务器端到客户端显示为蓝色。
#### 3.3.7 ActualThpt
此选项显示上传或者下载的速度。
#### 3.3.8 TotalBytes
显示的数值表示的是在两个方向（客户端到服务器和服务器到客户端）中交换的流量的总和。
### 3.4 Hosts
Hosts有一个下拉菜单，包含了一组与主机相关的信息页的链接。主要有：Hosts(所有主机）、Mac Addresses(Mac 地址）、Networks、Host Pools、Autonomous Systems（自主系统）、Countries、Operating Systems、Looking Glass、Sever HTTP、Top Hosts、Geo Map、Hosts Tree Map、Local Flow Matirx(顶级浮点阵）。
#### 3.4.1 Hosts
显示出所有的监视网络接口的主机，可以单击每一个标列题，使主机点击的标题按升序或降序排列。
主要的参数：IP Address、Location、Flows、Alerts、Name、seensince(观察到主机发送/接收的第一个分组以来的时间量）、Breakdown 、Throughput、TotalBytes。
#### 3.4.2 Host pool
此页面显示已经定义的和当前活动的主机池的列表信息。
#### 3.4.3 NetWorks
此页面显示对于发现的每一个network,ntopng显示出主机数、触发的警报、发现日期、故障、吞吐量、通信量等信息。
#### 3.4.4  Autonomous Systems
ntopng利用MAxmind数据库收集关于自治系统(AS)的信息，基于此将属于统一AS的主机进行分组。
### 3.5 InterFaces
顶部的工具栏中列出了ntopng当前监视的所有接口（interfaces)，在列出的所有接口中，有一个是当前选择接口的复选标记。可以通过点击接口来访问该接口流量。
每个接口都会出现许多参数的信息，包括：home、Pcakets、Protocols、ICMP、ARP、Statistic、Alerts等。
