#ifndef _LZFS_XATTR_H
#define _LZFS_XATTR_H
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
extern struct xattr_handler *lzfs_xattr_handlers[];
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
extern const struct xattr_handler *lzfs_xattr_handlers[];
#endif

ssize_t
lzfs_listxattr(struct dentry *dentry, char *buffer, size_t size);

extern struct xattr_handler lzfs_xattr_user_handler;
extern struct xattr_handler lzfs_xattr_acl_access_handler;
extern struct xattr_handler lzfs_xattr_acl_default_handler;
extern struct xattr_handler lzfs_xattr_security_handler;

int
lzfs_xattr_get(struct inode *inode, const char *name,
		void *buffer, size_t size, int);
int
lzfs_removexattr(struct dentry *dentry, const char *name);

int
lzfs_init_security(struct dentry *dentry, struct inode *dir);

int
lzfs_vnop_setattr(struct dentry *dentry, struct iattr *iattr);
int
lzfs_check_acl(struct inode *inode, int mask);
int
lzfs_acl_chmod(struct inode *inode);
int
lzfs_acl_init(struct inode *inode, struct inode *dir);

#endif /* _LZFS_XATTR_H */

