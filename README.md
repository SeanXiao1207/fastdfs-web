# fastdfs-web
一个fastdfs的页面程序

# 项目架构
一般是和fastdfs一起部署，也就是docker-compose.yml

# 界面
登录
<img width="1648" height="814" alt="image" src="https://github.com/user-attachments/assets/5b10b672-2b54-4c9b-a709-94e8dbdcd2f7" />
这里输入的密码就是上面docker-compose.yml文件中定义的ADMIN_PASSWORD值

首页
<img width="1882" height="910" alt="image" src="https://github.com/user-attachments/assets/2d695ff6-6eac-469e-adfc-dbc6b59fa502" />
1、可以退出登录；
2、可以搜索某个目录的内容，比如fdfs2中的某个文件；
3、分页查询目录内容（100条一页）；
4、扫描内容是会内存缓存，也就是目录首次点击会刷新所有数据，全部内存缓存，该缓存考虑到重启被清空的问题，加了固化文件的操作，也就是这里重启并不会要再次扫描，会从固化文件中获取；
5、图片内容可以查看和下载
