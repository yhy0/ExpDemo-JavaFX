## 0x01 这是个嘛？

这是一个构建图形化漏洞利用的一个项目，已经写好架子，只需要往里填充exp即可，帮助安全人员快速构建一个图形化的、跨平台的漏洞利用工具。

虽然有很多优秀的命令行利用工具，但我觉得还是带界面的方便、直观。

使用本项目，你不需要懂太多Java语言，只需要了解基本的语法，参考自带的EXP例子，即可快速开发一款**属于你自己**的漏洞利用工具，建立自己的漏洞利用库。

[ExpDemo-JavaFX工具新增漏洞编写教程](https://mp.weixin.qq.com/s/j5BHSbNZ76XbSZp6hFj9fw)

## 0x02 Demo

经过多次改版，这是最终(?)的效果。详细见[更新记录.md](更新记录.md)



https://user-images.githubusercontent.com/31311038/131443436-cbc91857-d19e-4721-b82c-eb160c2d8440.mp4




<video controls="controls" loop="loop" autoplay="autoplay"> 
    <source src="images/神机.mp4" type="video/mp4">
</video>


## 0x03 编写属于你的图像化漏洞利用工具

#### 3.1 项目结构

```apl
.
├── ExpDemo-JavaFX.iml
├── logs          运行日志文件
│   ├── debug.log
│   └── error.log
├── pom.xml
└── src
    └── main
        ├── java
        │   └── fun
        │       └── fireline
        │           ├── AppStartUp.java    应用程序启动入口
        │           ├── controller    控制JavaFX图形化界面的各种显示、事件等，核心代码 
        │           │   ├── MainController.java  主界面的controller，负责切换界面和基本信息显示
        │           │   ├── OAController.java   OA漏洞利用切换界面的相关逻辑
        │           │   ├── OthersController.java  其他漏洞界面的相关逻辑
        │           │   ├── Struts2Controller.java  Struts2漏洞利用界面的相关逻辑
        │           │   └── oa      OA漏洞利用的相关逻辑
        │           │       └── OASeeyonController.java
        │           ├── core     核心代码文件夹
        │           │   ├── Constants.java   一些常量基本信息
        │           │   ├── ExploitInterface.java   exp 编写要实现的接口
        │           │   ├── Job.java    一种漏洞全部检查的类
        │           │   └── VulInfo.java
        │           ├── exp			各种 exp 实现类
        │           │   ├── apache
        │           │   │   └── struts2
        │           │   │       ├── S2_005.java
        │           │   │       ├── S2_009.java
        │           │   │       ├── S2_016.java
        │           │   │       ├── S2_019.java
        │           │   │       ├── S2_032.java
        │           │   │       ├── S2_045.java
        │           │   │       ├── S2_046.java
        │           │   │       └── S2_DevMode.java
        │           │   ├── cms
        │           │   │   └── nc
        │           │   │       └── CNVD_2021_30167.java
        │           │   ├── oracle
        │           │   │   └── CVE_2020_14882.java
        │           │   └── others
        │           │       └── CVE_2021_22986.java
        │           └── tools  工具文件夹
        │               ├── HttpTool.java  HTTP 请求封装
        │               ├── MyCERT.java    HTTPS 请求证书设置
        │               └── Tools.java     一些处理函数
        └── resources    资源文件夹
            ├── css      界面css样式表
            │   └── main.css
            ├── fxml    界面的设计文件
            │   ├── Main.fxml
            │   ├── OA.fxml
            │   ├── Others.fxml
            │   ├── Struts2.fxml
            │   ├── Weblogic.fxml
            │   └── oa
            │       ├── OA-E-office.fxml
            │       ├── OA-Kingdee.fxml
            │       ├── OA-Landray.fxml
            │       └── OA-Seeyon.fxml
            ├── img
            │   ├── sec.png
            │   └── weixin.jpg
            └── log4j.properties   日志相关设置
```

#### 3.2 编写EXP

编写EXP时，要使用 `implements`实现`ExploitInterface`接口，实现接口中的几个方法

![image-20210327190517731](https://cdn.jsdelivr.net/gh/yhy0/PicGoImg@master/JavaFX/20210818133114.png)

-   checkVUL		使用poc 检查是否漏洞
-   exeCMD          使用exp执行命令
-   uploadFile        使用命令执行 写webshell，上传文件
-   getWebPath     获取网站的web目录，供上传文件使用
-   isVul                是否存在漏洞，检查时会根据结构自动赋值，供后续调用

EXP具体编写请参考 `fun/fireline/exp` 下的各种漏洞实现

当编写完EXP后，转到 `fun/fireline/controller` 下对应的**xxController.java**文件，比如新编写了Struts2的相关漏洞，修改**Struts2Controller.java**的**STRUTS2**变量，新加入一个漏洞名称，这里对应的是图像化界面中可供选择的漏洞列表

![image-20210818125816864](https://cdn.jsdelivr.net/gh/yhy0/PicGoImg@master/JavaFX/20210818133131.png)

之后进入和 `fun/fireline/tools/Tools.java` 的**getExploit**方法中新增一个**else if**

![image-20210818130128550](https://cdn.jsdelivr.net/gh/yhy0/PicGoImg@master/JavaFX/20210818133137.png)

编写完后，可以直接执行`fun/fireline/AppStartUp.java`类, 查看是否正常运行。

开发过程中每次修改完运行前，最好将生成的**target**目录删除再运行

#### 3.3 新增漏洞页面

具体请看[更新记录.md](更新记录.md)

[ExpDemo-JavaFX工具新增漏洞编写教程](https://mp.weixin.qq.com/s/j5BHSbNZ76XbSZp6hFj9fw)

#### 3.4 部署，发布

当一切编写完成，bug修复完毕，在项目根目录下执行 **mvn package assembly:single** 即可生成 **jar** 文件。

运行使用**target目录下最大的jar文件** 

对方没有Java环境怎么办？

使用 **mvn jfx:native** 命令生产对应平台的文件，比如Mac下，执行命令**mvn jfx:native**命令就会在 **target/jfx/native** 目录下生成打包后应用(win下生成exe)，带可执行文件，带 JRE 运行环境，超大，200+M。

 **mvn clean**用于清除生成的文件。

## 0x05 免责声明

本工具仅能在取得足够合法授权的企业安全建设中使用，在使用本工具过程中，您应确保自己所有行为符合当地的法律法规。

如您在使用本工具的过程中存在任何非法行为，您将自行承担所有后果，本工具所有开发者和所有贡献者不承担任何法律及连带责任。

除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。

您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

## 开心指数

[![Stargazers over time](https://starchart.cc/yhy0/ExpDemo-JavaFX.svg)](https://starchart.cc/yhy0/ExpDemo-JavaFX)
