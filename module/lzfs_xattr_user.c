#include <linux/fs.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/lzfs_inode.h>
#include <sys/lzfs_xattr.h>
#include <linux/xattr.h>

static int
lzfs_xattr_user_get(struct inode *inode, const char *name,
                    void *buffer, size_t size)
{
	if(strcmp(name,"") == 0) {
		return -EINVAL;
	}

	return lzfs_xattr_get(inode, name, buffer, size);
}

static int      
lzfs_xattr_user_set(struct inode *inode, const char *name,
                    const void *value, size_t size, int flags)
{               

	printk("name is : %s, value is : %s, size is :%ld", name, ( char *) value, (long)size);
	return -EOPNOTSUPP;	
}

static size_t
lzfs_xattr_user_list(struct inode *inode, char *list, size_t list_size,
                     const char *name, size_t name_len)
{   
	return 0;            
}


struct xattr_handler lzfs_xattr_user_handler = {
        .prefix = XATTR_USER_PREFIX,
     .list   = lzfs_xattr_user_list,
        .get    = lzfs_xattr_user_get,
        .set    = lzfs_xattr_user_set,
};

