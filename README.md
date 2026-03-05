# fastdfs-web
一个fastdfs的页面程序

# 项目架构
### 一般是和fastdfs一起部署，也就是docker-compose.yml分别定义了fastdfs-web、tracker、storage0 三个容器；
### 然后fastdfs-web 中 sh -c "pip install flask gunicorn -q && gunicorn -w 1 -b 0.0.0.0:8088 --timeout 300 --chdir /opt/fdfs app:app" 就会找宿主机/opt/fdfs/app.py文件运行；
### 由此 服务器 /opt/fdfs/ 目录需要放app.py文件（同时还是fastdfs 数据存储目录），然后运行 docker compose up -d 在 docker-compose.yml 文件所在目录。

### 这个 fastdfs-web的核心就是用一个python3容器，跑一个app.py的脚本，而这个脚本就是一个web程序。
### 默认是绑定了8088端口，具体可以自行修改docker-compose.yml，其中还有加密等处理。

# 界面
登录
<img width="1648" height="814" alt="image" src="https://github.com/user-attachments/assets/5b10b672-2b54-4c9b-a709-94e8dbdcd2f7" />
### 这里输入的密码就是上面docker-compose.yml文件中定义的ADMIN_PASSWORD值

首页
<img width="1882" height="910" alt="image" src="https://github.com/user-attachments/assets/2d695ff6-6eac-469e-adfc-dbc6b59fa502" />
### 1、可以退出登录；
### 2、可以搜索某个目录的内容，比如fdfs2中的某个文件；
### 3、分页查询目录内容（100条一页）；
### 4、扫描内容是会内存缓存，也就是目录首次点击会刷新所有数据，全部内存缓存，该缓存考虑到重启被清空的问题，加了固化文件的操作，也就是这里重启并不会要再次扫描，会从固化文件中获取；
### 5、图片内容可以查看和下载
