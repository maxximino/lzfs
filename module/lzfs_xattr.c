#include <linux/fs.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/lzfs_inode.h>
#include <sys/lzfs_xattr.h>

int
lzfs_xattr_get(struct inode *inode, const char *name,
                    void *buffer, size_t size)
{
	char *tmp = "hello world";
	int error = 0;
	printk("name=%s, buffer=%p, buffer_size=%ld",
                   name, buffer, (long)size);	
	if(buffer) {
		memcpy(buffer, (void *)tmp, 12);
		error = 12;
	}
	return error;
}



struct xattr_handler *lzfs_xattr_handlers[] = {
        &lzfs_xattr_user_handler,
//        &lzfs_xattr_trusted_handler,
#ifdef CONFIG_EXT2_FS_POSIX_ACL
  //      &lzfs_xattr_acl_access_handler,
    //    &lzfs_xattr_acl_default_handler,
#endif  
#ifdef CONFIG_EXT2_FS_SECURITY
      //  &lzfs_xattr_security_handler,
#endif          
        NULL
};


